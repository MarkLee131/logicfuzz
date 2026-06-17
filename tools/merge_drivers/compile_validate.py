"""Compile-validation for merge candidates — keep the merged harness VALID.

First principle: the merge's contract is to produce a VALID multi-driver
harness. If every included sub-driver TU *compiles* under the OSS-Fuzz build
flags, then both the address build (``--sanitizer address``, what the fuzzer
runs) and the coverage build (``--sanitizer coverage``, what coverage replay
measures) compile the identical valid set — no ``|| continue`` skip fires and
no ``entry.{c,cpp}`` weak stub shadows a real driver. A≡B between the two builds
is then a *consequence* of "only valid drivers shipped", not something we
engineer directly.

Without this gate, a COMPILE-INVALID candidate (``void name[2]`` void-arrays,
undeclared ``cmsSig*`` constants, struct-vs-pointer mismatch,
``#include "lcms2_internal.h"``) slips through preflight (which only smoke-RUNS
drivers that already have a host-runnable binary — a driver that can't build has
none, and "couldn't vet" means "keep"). The merged build then skips that
non-compiling TU (``merge.py`` ``|| continue``) and the weak stub fills its
symbol, so the slot becomes a silent no-op: the portfolio loses the driver and
coverage replay reads 0 on it.

This module compiles each candidate TU **inside the real OSS-Fuzz build
container under the COVERAGE-build compile flags** (the measurement build — the
one whose 0-coverage divergence we are fixing) with ``-fsyntax-only`` (fast: no
codegen, no link, one container, once) and returns the compile-valid subset.
The ``|| continue`` + weak stub in ``merge.py`` remain as a now-rarely-firing
SAFETY NET — we just stop relying on them as the primary mechanism.

Two faithfulness details make the syntax check match the real merged build:
  * each TU is compiled in the LANGUAGE the merge will use for it (C vs C++ per
    ``IndividualDriver.suffix``), not a try-both fallback that masks C-invalid
    code (see ``_merge_target_lang``); and
  * ``-Werror=implicit-function-declaration`` / ``-Werror=implicit-int`` are
    re-promoted for C TUs, because a driver that CALLS a real library function
    without declaring it only WARNS at compile (project ``$CFLAGS`` has
    ``-Wno-error=…``) but fails the merged LINK with ``undefined reference`` —
    ``-fsyntax-only`` can't see a link error, so promoting these two catches the
    class without paying for a full link.

Reuses the same image/build machinery the eval already uses
(``experiment.oss_fuzz_checkout`` → ``gcr.io/oss-fuzz/<project>``) and the SAME
include-discovery (``EXT_INC``) that ``scripts/run_extended_fuzzing.py`` and the
``merge.py`` build snippet use, so a TU that passes here is a TU that will
compile in the real merged build.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

# Each candidate is validated in EXACTLY the language the merged build will
# compile it as — NOT "try C then fall back to C++". The merge renames a driver
# into ``<id>.c`` or ``<id>.cpp`` based on ``IndividualDriver.suffix`` (real
# extension → C++-marker content sniff → default C) and the build snippet then
# compiles ``.c`` with ``$CC`` (C) and ``.cpp`` with ``$CXX`` (C++). A
# try-C-then-C++ fallback would GREEN-LIGHT a C-default driver that only compiles
# as C++ (e.g. ``_cmsContext_struct *foo;`` — legal C++, rejected by C's
# "must use 'struct' tag") — exactly the silent no-op the gate must catch. So we
# resolve each candidate's merge-target language up front and compile it once in
# that language only, making the check faithful to the real merged build.
_DEFAULT_TIMEOUT_SEC = 600


def _merge_target_lang(src: Path) -> str:
    """The language ('c' or 'cpp') the MERGED build will compile ``src`` as —
    reusing the exact ``IndividualDriver.suffix`` logic so validation and the
    merge agree. Falls back to extension-only (then C) if merge.py is
    unavailable, so this module never hard-depends on the merge import."""
    try:
        from tools.merge_drivers.merge import IndividualDriver
        return IndividualDriver(driver_path=src, index=0).suffix
    except Exception:  # noqa: BLE001
        ext = src.suffix.lstrip('.').lower()
        return 'cpp' if ext in ('cc', 'cpp', 'cxx') else 'c'


@dataclass
class _TuVerdict:
    name: str           # basename of the candidate source
    ok: bool
    error_tail: str     # last lines of the compiler stderr when not ok


def _resolve_oss_fuzz_dir() -> Path:
    """Locate the OSS-Fuzz checkout the eval uses (same resolution path as
    scripts/run_extended_fuzzing.ExtendedFuzzer._get_oss_fuzz_dir)."""
    from experiment import oss_fuzz_checkout
    d = Path(oss_fuzz_checkout.OSS_FUZZ_DIR)
    if (d / 'projects').is_dir():
        return d
    if oss_fuzz_checkout.GLOBAL_TEMP_DIR:
        return Path(oss_fuzz_checkout.GLOBAL_TEMP_DIR)
    # Clone on demand (rare — eval has normally checked it out already).
    oss_fuzz_checkout.clone_oss_fuzz()
    return Path(oss_fuzz_checkout.OSS_FUZZ_DIR)


def _ensure_project_image(project: str) -> Optional[str]:
    """Return a usable ``gcr.io/oss-fuzz/<project>`` image tag, building it via
    the SAME helper the eval uses if it isn't cached. Returns None if no image
    can be obtained (caller then skips the gate rather than blocking the merge).
    """
    tag = f'gcr.io/oss-fuzz/{project}'
    # Fast path: the eval almost always built this already.
    inspect = subprocess.run(['docker', 'image', 'inspect', tag],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    if inspect.returncode == 0:
        return tag

    # Build it via experiment.oss_fuzz_checkout._build_image (clones/copies the
    # project Dockerfile + reuses any base image). Make sure the project dir
    # exists in the checkout first (clone_oss_fuzz populates projects/).
    try:
        from experiment import oss_fuzz_checkout
        oss_dir = _resolve_oss_fuzz_dir()
        proj_dir = oss_dir / 'projects' / project
        if not proj_dir.is_dir():
            logger.warning(
                'compile_validate: project %s not in OSS-Fuzz checkout %s; '
                'cannot build image', project, oss_dir)
            return None
        built = oss_fuzz_checkout._build_image(project)  # noqa: SLF001
        return built or None
    except Exception as exc:  # noqa: BLE001 — never block the merge
        logger.warning('compile_validate: image build failed (%s); '
                       'skipping gate', exc)
        return None


# Bash run INSIDE the project image. Mirrors the include-discovery + per-TU
# compile that the merged OSS-Fuzz build snippet / run_extended_fuzzing use,
# but with -fsyntax-only (no .o, no link). Validates under the COVERAGE build's
# compile flags: $CFLAGS already carries the project's -Wno-error relaxations and
# -DFUZZING_BUILD_MODE...; $SANITIZER_FLAGS_coverage is "" and
# $COVERAGE_FLAGS_coverage is codegen/link-only (-fprofile-instr-generate /
# -fcoverage-mapping) — none of which change WHICH TUs compile — so appending
# them makes this literally the coverage build's compile while staying robust if
# they're ever made stricter.
#
# Each candidate is compiled in its MERGE-TARGET language only (read from the
# ``.langs`` manifest: ``<staged_name> <c|cpp>`` per line) so a C-default driver
# is checked as C (``$CC``/``-x c``) — the same compiler the merge uses for its
# ``<id>.c`` — and a C++ driver as C++ (``$CXX``/``-x c++``). No try-both
# fallback, which would mask C-invalid TUs. Prints one "RESULT <ok|fail> <name>".
_VALIDATE_SH = r'''
set -u
PROJ="__PROJECT__"
EXT_INC=""
for d in /src/$PROJ/include /src/$PROJ /src/$PROJ/src /src/include /src; do
  [ -d "$d" ] && EXT_INC="$EXT_INC -I$d"
done
# Populate configure/cmake-generated headers (e.g. c-ares ares_build.h) so the
# syntax check sees the SAME tree the real merged coverage build compiles (A≡B).
# Best-effort + fail-open: a failing/absent build must never drop candidates.
( compile >/dev/null 2>&1 || bash /src/build.sh >/dev/null 2>&1 || true )
for g in $(find /src/$PROJ /work \( -name '*_build.h' -o -name '*_config.h' \) 2>/dev/null); do
  EXT_INC="$EXT_INC -I$(dirname "$g")"
done
# Generated drivers may carry the project's own fuzzer include idiom, e.g. cjson's
# stock harness lives in /src/cjson/fuzzing/ and does ``#include "../cJSON.h"``.
# Such an explicit ``../`` path resolves relative to the SOURCE file's dir
# (/candidates/ here → /X.h), which -I cannot fix. Symlink every project header to
# the ``../`` target (/) so the same relative include the real per-driver build
# accepts also resolves here (A≡B). Best-effort; never fails the gate.
for d in /src/$PROJ /src/$PROJ/include /src/$PROJ/src; do
  [ -d "$d" ] || continue
  for h in "$d"/*.h "$d"/*.hpp; do
    [ -e "$h" ] && ln -sf "$h" "/$(basename "$h")" 2>/dev/null || true
  done
done
COV_FLAGS="${SANITIZER_FLAGS_coverage:-} ${COVERAGE_FLAGS_coverage:-}"
# The project $CFLAGS carries ``-Wno-error=implicit-function-declaration`` and
# ``-Wno-error=implicit-int`` — so a C driver that CALLS a real library function
# WITHOUT declaring it (missing #include) only WARNS at compile and produces an
# object, then fails the merged LINK with ``undefined reference`` → that slot
# becomes a broken no-op. ``-fsyntax-only`` alone can't see a link error, so we
# re-promote exactly these two to ERRORS (after $CFLAGS, so they override the
# -Wno-error): an undeclared-call driver is then correctly EXCLUDED, matching
# what the merged build's link would do. (C-only; harmless in C++ which already
# errors on undeclared calls.)
STRICT_C="-Werror=implicit-function-declaration -Werror=implicit-int"
while read -r b lang; do
  [ -n "$b" ] || continue
  src="/candidates/$b"
  [ -f "$src" ] || continue
  err=$(mktemp)
  if [ "$lang" = "cpp" ]; then
    cc_ok=1; $CXX $CXXFLAGS $COV_FLAGS $EXT_INC -x c++ -fsyntax-only "$src" 2>"$err" || cc_ok=0
  else
    cc_ok=1; $CC $CFLAGS $COV_FLAGS $STRICT_C $EXT_INC -x c -fsyntax-only "$src" 2>"$err" || cc_ok=0
  fi
  if [ "$cc_ok" = "1" ]; then
    echo "RESULT ok $b"
  else
    echo "RESULT fail $b"
    echo "ERRBEGIN $b"
    # Prefer the actual ``error:`` diagnostic lines (skip caret/note noise);
    # fall back to the stderr tail if none matched.
    if grep -m 3 "error:" "$err" >/dev/null 2>&1; then
      grep -m 3 "error:" "$err"
    else
      tail -n 4 "$err"
    fi
    echo "ERREND $b"
  fi
done < /candidates/.langs
echo "VALIDATE_DONE"
'''


def _run_container_validation(
    image: str,
    candidates_dir: Path,
    project: str,
    timeout_sec: int,
) -> Optional[List[_TuVerdict]]:
    """Compile every file in ``candidates_dir`` inside ``image``; parse verdicts.

    Returns None on infra failure (container couldn't run / no terminator seen)
    so the caller can fail OPEN (keep the unvetted set) rather than dropping
    everything on a docker hiccup.
    """
    script = _VALIDATE_SH.replace('__PROJECT__', project)
    # NAME channel container-leak fix: `image` is the BARE base
    # gcr.io/oss-fuzz/<project> (shared / a user's interactive shell may run it),
    # so ancestor-scoped cleanup would be unsafe. Give the container a UNIQUE
    # --name and force-remove BY NAME in a finally — `--rm` does not fire if the
    # docker-run client is killed on timeout. See experiment.container_cleanup.
    try:
        from experiment import container_cleanup as _cc
        _ctr_name = _cc.make_container_name('compileval')
    except Exception:  # standalone/test contexts without the package on path
        _cc = None
        _ctr_name = ''
    cmd = [
        'docker', 'run', '--rm',
    ] + (['--name', _ctr_name] if _ctr_name else []) + [
        '-v', f'{candidates_dir.resolve()}:/candidates:ro',
        image, 'bash', '-c', script,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        logger.warning('compile_validate: container timed out after %ds; '
                       'failing open (merging unvetted)', timeout_sec)
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning('compile_validate: container run failed (%s); '
                       'failing open', exc)
        return None
    finally:
        if _cc is not None and _ctr_name:
            _cc.force_remove_named_container(_ctr_name)

    out = proc.stdout or ''
    if 'VALIDATE_DONE' not in out:
        logger.warning(
            'compile_validate: validation did not complete (rc=%s); failing '
            'open. stderr tail:\n%s', proc.returncode,
            (proc.stderr or '')[-800:])
        return None

    verdicts: List[_TuVerdict] = []
    err_map: dict = {}
    cur_err_name = None
    cur_err_lines: List[str] = []
    for line in out.splitlines():
        if line.startswith('RESULT '):
            _, status, name = line.split(' ', 2)
            verdicts.append(_TuVerdict(name=name, ok=(status == 'ok'),
                                       error_tail=''))
        elif line.startswith('ERRBEGIN '):
            cur_err_name = line[len('ERRBEGIN '):]
            cur_err_lines = []
        elif line.startswith('ERREND '):
            if cur_err_name is not None:
                err_map[cur_err_name] = '\n'.join(cur_err_lines).strip()
            cur_err_name = None
        elif cur_err_name is not None:
            cur_err_lines.append(line)

    for v in verdicts:
        if not v.ok:
            v.error_tail = err_map.get(v.name, '')
    return verdicts


def validate_compilable(
    sources: Sequence[Path],
    project: str,
    timeout_sec: int = _DEFAULT_TIMEOUT_SEC,
) -> Tuple[List[Path], List[Tuple[Path, str]]]:
    """Compile each candidate TU in the project's OSS-Fuzz container and split
    them into (valid, excluded).

    valid    — sources that compiled under -fsyntax-only with the coverage-build
               compile flags. These are safe to ship into synthesized/.
    excluded — [(source, reason)] for each TU that FAILED to compile (or, on
               infra failure, an empty list with everything kept — fail OPEN).

    On any infra problem (docker missing, no project image, container hiccup)
    this returns (all sources, []) — it must never BLOCK a merge, only PRUNE
    known-bad TUs. The merge's existing weak-stub safety net still catches a
    stray non-compiler that slips past (e.g. a flag-skew false-pass).
    """
    sources = [Path(s) for s in sources]
    if not sources:
        return [], []

    if shutil.which('docker') is None:
        logger.warning('compile_validate: docker not on PATH; skipping gate '
                       '(merging unvetted)')
        return list(sources), []

    image = _ensure_project_image(project)
    if not image:
        logger.warning('compile_validate: no project image for %s; skipping '
                       'gate (merging unvetted)', project)
        return list(sources), []

    # Stage candidates into one temp dir under STABLE, collision-free names so a
    # single container compiles them all. Map staged-name → original path.
    import tempfile
    staging = Path(tempfile.mkdtemp(prefix=f'lf_compileval_{project}_'))
    name_to_src: dict = {}
    manifest_lines: List[str] = []
    try:
        for i, src in enumerate(sources):
            staged = staging / f'{i:03d}_{src.name}'
            shutil.copy(src, staged)
            name_to_src[staged.name] = src
            # Resolve the merge-target language NOW so the container compiles
            # each TU exactly as the merged build will (C vs C++ is decided by
            # IndividualDriver.suffix on the original source).
            manifest_lines.append(f'{staged.name} {_merge_target_lang(src)}')
        (staging / '.langs').write_text('\n'.join(manifest_lines) + '\n')

        verdicts = _run_container_validation(image, staging, project,
                                             timeout_sec)
        if verdicts is None:
            # Infra failure → fail open.
            return list(sources), []

        seen = {v.name for v in verdicts}
        valid: List[Path] = []
        excluded: List[Tuple[Path, str]] = []
        for v in verdicts:
            src = name_to_src.get(v.name)
            if src is None:
                continue
            if v.ok:
                valid.append(src)
            else:
                reason = v.error_tail or 'compile error (no diagnostic captured)'
                excluded.append((src, reason))
        # Any candidate the container never reported on (shouldn't happen) is
        # kept — fail open per-TU, never drop something we didn't actually vet.
        for staged_name, src in name_to_src.items():
            if staged_name not in seen:
                valid.append(src)
                logger.warning('compile_validate: no verdict for %s; keeping '
                               '(unvetted)', src.name)
        return valid, excluded
    finally:
        shutil.rmtree(staging, ignore_errors=True)
