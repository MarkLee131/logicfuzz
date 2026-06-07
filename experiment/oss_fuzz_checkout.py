# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Tools used for experiments.
"""
import atexit
import logging
import os
import re
import shutil
import subprocess as sp
import tempfile
import uuid

import yaml

from experiment import benchmark as benchmarklib

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

BUILD_DIR: str = 'build'
GLOBAL_TEMP_DIR: str = ''
ENABLE_CACHING = bool(int(os.getenv('OFG_USE_CACHING', '0')))

# --- Library build-cache (LOGICFUZZ_LIB_CACHE) ----------------------------
# Default OFF. When ON, the project's library is compiled ONCE per run into a
# committed Docker image (per sanitizer). Every trial then FROMs that image and
# runs a *reduced* build script that only recompiles+links the one-file fuzz
# driver, instead of re-running ``./configure && make`` (a full library rebuild)
# inside every ``docker run ... compile``.
#
# Why this exists: each trial's build (build_target_local -> docker run compile)
# executes the project's UNMODIFIED build.sh, which for autotools/cmake projects
# (e.g. lcms: ``./configure --enable-shared=no && make -j$(nproc) all``) rebuilds
# the entire library before compiling the single driver .c. The library is
# byte-identical across trials, so that work is pure waste — measured ~57 full
# lcms library rebuilds for a 56-driver run.
#
# This is the upstream OSS-Fuzz "ofg-cached" idea (commit a post-build container,
# FROM it, swap in a reduced build script) but self-contained and auto-derived,
# so it needs no hand-written ``fuzzer_build_script/<project>`` gate file and no
# remote registry.
#
# Fail-safe contract: any error in cache preparation, or an un-reducible
# build.sh, leaves ``_LIB_CACHE_READY`` empty for that (project, sanitizer) and
# every consumer (build_target_local) falls back to the normal full build —
# slower but correct. Default-off means behaviour is byte-identical to before
# unless explicitly enabled.
LIB_CACHE_ENABLED = bool(int(os.getenv('LOGICFUZZ_LIB_CACHE', '0')))
# (project, sanitizer) -> reduced build.sh text. Populated by
# prepare_library_cache; presence means the committed image was built.
_LIB_CACHE_READY: dict = {}
# Assume OSS-Fuzz is at repo root dir by default.
# This will change if temp_dir is used.
OSS_FUZZ_DIR: str = os.path.join(
    os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'oss-fuzz')
CLEAN_UP_OSS_FUZZ = bool(int(os.getenv('OFG_CLEAN_UP_OSS_FUZZ', '1')))

VENV_DIR: str = 'venv'


def _remove_temp_oss_fuzz_repo():
  """Deletes the temporary OSS-Fuzz directory."""
  # Ensure we aren't deleting a real repo someone cares about.
  assert not OSS_FUZZ_DIR.endswith('oss-fuzz')
  try:
    shutil.rmtree(OSS_FUZZ_DIR)
  except PermissionError as e:
    logger.warning('No permission to remove %s: %s', OSS_FUZZ_DIR, e)
  except FileNotFoundError as e:
    logger.warning('No OSS-Fuzz directory %s: %s', OSS_FUZZ_DIR, e)


def _set_temp_oss_fuzz_repo():
  """Creates a temporary directory for OSS-Fuzz repo and update |OSS_FUZZ_DIR|.
  """
  # Holding the temp directory in a global object to ensure it won't be deleted
  # before program ends.
  global GLOBAL_TEMP_DIR
  GLOBAL_TEMP_DIR = tempfile.mkdtemp()
  global OSS_FUZZ_DIR
  OSS_FUZZ_DIR = GLOBAL_TEMP_DIR
  atexit.register(_remove_temp_oss_fuzz_repo)
  _clone_oss_fuzz_repo()


def _clone_oss_fuzz_repo():
  """Clones OSS-Fuzz to |OSS_FUZZ_DIR|."""
  clone_command = [
      'git', 'clone', 'https://github.com/google/oss-fuzz', '--depth', '1',
      OSS_FUZZ_DIR
  ]
  proc = sp.Popen(clone_command,
                  stdout=sp.PIPE,
                  stderr=sp.PIPE,
                  stdin=sp.DEVNULL)
  stdout, stderr = proc.communicate()
  if proc.returncode != 0:
    logger.info(stdout)
    logger.info(stderr)


def clone_oss_fuzz(oss_fuzz_dir: str = ''):
  """Clones the OSS-Fuzz repository."""
  if oss_fuzz_dir:
    global OSS_FUZZ_DIR
    OSS_FUZZ_DIR = oss_fuzz_dir
  else:
    _set_temp_oss_fuzz_repo()

  if not os.path.exists(OSS_FUZZ_DIR):
    _clone_oss_fuzz_repo()

  if CLEAN_UP_OSS_FUZZ:
    clean_command = ['git', 'clean', '-fxd', '-e', VENV_DIR, '-e', BUILD_DIR]
    sp.run(clean_command,
           capture_output=True,
           stdin=sp.DEVNULL,
           check=True,
           cwd=OSS_FUZZ_DIR)

  # Sync oss-fuzz data if needed.
  if os.environ.get('OSS_FUZZ_DATA_DIR', ''):
    src_projects = os.path.join(os.environ['OSS_FUZZ_DATA_DIR'], 'projects')
    logger.info('OSS_FUZZ_DATA_DIR: %s', os.environ['OSS_FUZZ_DATA_DIR'])
    logger.info('src_projects: %s', src_projects)
    for proj in os.listdir(src_projects):
      src_project = os.path.join(src_projects, proj)
      dst_project = os.path.join(OSS_FUZZ_DIR, 'projects', proj)
      logger.info('Copying: %s to %s', src_project, dst_project)
      shutil.copytree(src_project, dst_project)


def postprocess_oss_fuzz() -> None:
  """Prepares the oss-fuzz directory for experiments."""
  # Write .gcloudignore to make submitting to GCB faster.
  with open(os.path.join(OSS_FUZZ_DIR, '.gcloudignore'), 'w') as f:
    f.write('__pycache__\n')
    f.write('build\n')
    f.write('.git\n')
    f.write('.pytest_cache\n')
    f.write('venv\n')

  # Set up dependencies to run OSS-Fuzz build scripts
  if os.path.exists(os.path.join(OSS_FUZZ_DIR, VENV_DIR)):
    return

  # If already in a virtualenv environment assume all is set up
  venv_path = os.path.split(os.environ.get('VIRTUAL_ENV', ''))
  if venv_path and venv_path[0].endswith(os.path.split(OSS_FUZZ_DIR)[-1]):
    return

  result = sp.run(['python3', '-m', 'venv', VENV_DIR],
                  check=True,
                  capture_output=True,
                  stdin=sp.DEVNULL,
                  cwd=OSS_FUZZ_DIR)
  result = sp.run([
      f'./{VENV_DIR}/bin/pip', 'install', '-r',
      'infra/build/functions/requirements.txt'
  ],
                  check=True,
                  cwd=OSS_FUZZ_DIR,
                  stdin=sp.DEVNULL,
                  capture_output=True)
  if result.returncode:
    logger.info('Failed to postprocess OSS-Fuzz (%s)', OSS_FUZZ_DIR)
    logger.info('stdout: %s', result.stdout)
    logger.info('stderr: %s', result.stderr)


def list_c_cpp_projects() -> list[str]:
  """Returns a list of all c/c++ projects from oss-fuzz."""
  projects = []
  clone_oss_fuzz()
  projects_dir = os.path.join(OSS_FUZZ_DIR, 'projects')
  for project in os.listdir(projects_dir):
    project_yaml_path = os.path.join(projects_dir, project, 'project.yaml')
    with open(project_yaml_path) as yaml_file:
      config = yaml_file.read()
      if 'language: c' in config:
        projects.append(project)
  return sorted(projects)


def get_project_language(project: str) -> str:
  """Returns the |project| language read from its project.yaml."""
  project_yaml_path = os.path.join(OSS_FUZZ_DIR, 'projects', project,
                                   'project.yaml')
  if not os.path.isfile(project_yaml_path):
    logger.warning('Failed to find the project yaml of %s, assuming it is C++',
                   project)
    return 'C++'

  with open(project_yaml_path, 'r') as benchmark_file:
    data = yaml.safe_load(benchmark_file)
    return data.get('language', 'C++')


def get_project_repository(project: str) -> str:
  """Returns the |project| repository read from its project.yaml."""
  project_yaml_path = os.path.join(OSS_FUZZ_DIR, 'projects', project,
                                   'project.yaml')
  if not os.path.isfile(project_yaml_path):
    logger.warning(
        'Failed to find the project yaml of %s, return empty repository',
        project)
    return ''

  with open(project_yaml_path, 'r') as benchmark_file:
    data = yaml.safe_load(benchmark_file)
    return data.get('main_repo', '')


def _get_project_cache_name(project: str) -> str:
  """Gets name of cached container for a project."""
  return f'gcr.io.oss-fuzz.{project}_cache'


def _get_project_cache_image_name(project: str, sanitizer: str) -> str:
  """Gets name of cached Docker image for a project and a respective
  sanitizer."""
  return ('us-central1-docker.pkg.dev/oss-fuzz/oss-fuzz-gen/'
          f'{project}-ofg-cached-{sanitizer}')


def _has_cache_build_script(project: str) -> bool:
  """Checks if a project has cached fuzzer build script."""
  cached_build_script = os.path.join('fuzzer_build_script', project)
  return os.path.isfile(cached_build_script)


def _prepare_image_cache(project: str) -> bool:
  """Prepares cached images of fuzzer build containers."""
  # Only create a cached image if we have a post-build build script
  if not _has_cache_build_script(project):
    logger.info('No cached script for %s', project)
    return False
  logger.info('%s has a cached build script', project)

  cached_container_name = _get_project_cache_name(project)
  adjusted_env = os.environ | {
      'OSS_FUZZ_SAVE_CONTAINERS_NAME': cached_container_name
  }

  logger.info('Creating a cached images')
  for sanitizer in ['address', 'coverage']:
    if is_image_cached(project, sanitizer):
      logger.info('%s::%s is already cached, reusing existing cache.', project,
                  sanitizer)
      continue

    # Pull the cache first
    pull_cmd = [
        'docker', 'pull',
        _get_project_cache_image_name(project, sanitizer)
    ]
    try:
      sp.run(pull_cmd, check=True)
      logger.info('Successfully pulled cache image for %s', project)
    except sp.CalledProcessError:
      logger.info('Failed pulling image for %s', project)

    if is_image_cached(project, sanitizer):
      logger.info('pulled image for %s::%s', project, sanitizer)
      continue

    # If pull did not work, create cached image by building using OSS-Fuzz
    # with set variable. Fail if this does not work.
    command = [
        'python3', 'infra/helper.py', 'build_fuzzers', project, '--sanitizer',
        sanitizer
    ]
    try:
      sp.run(command, cwd=OSS_FUZZ_DIR, env=adjusted_env, check=True)
    except sp.CalledProcessError:
      logger.info('Failed to build fuzzer for %s.', project)
      return False

    # Commit the container to an image
    cached_image_name = _get_project_cache_image_name(project, sanitizer)

    command = ['docker', 'commit', cached_container_name, cached_image_name]
    try:
      sp.run(command, check=True)
    except sp.CalledProcessError:
      logger.info('Could not rename image.')
      return False
    logger.info('Created cached image %s', cached_image_name)

    # Delete the container we created
    command = ['docker', 'container', 'rm', cached_container_name]
    try:
      sp.run(command, check=True)
    except sp.CalledProcessError:
      logger.info('Could not rename image.')
  return True


def prepare_cached_images(
    experiment_targets: list[benchmarklib.Benchmark]) -> None:
  """Builds cached Docker images for a set of targets."""
  all_projects = set()
  for benchmark in experiment_targets:
    all_projects.add(benchmark.project)

  logger.info('Preparing cache for %d projects', len(all_projects))

  for project in all_projects:
    _prepare_image_cache(project)


def is_image_cached(project_name: str, sanitizer: str) -> bool:
  """Checks whether a project has a cached Docker image post fuzzer
  building."""
  cached_image_name = _get_project_cache_image_name(project_name, sanitizer)
  try:
    sp.run(
        ['docker', 'manifest', 'inspect', cached_image_name],
        check=True,
        stdin=sp.DEVNULL,
        stdout=sp.DEVNULL,
        stderr=sp.STDOUT,
    )
    return True
  except sp.CalledProcessError:
    return False


def rewrite_project_to_cached_project(project_name: str, generated_project: str,
                                      sanitizer: str) -> None:
  """Rewrites Dockerfile of a project to enable cached build scripts."""
  cached_image_name = _get_project_cache_image_name(project_name, sanitizer)
  generated_project_folder = os.path.join(OSS_FUZZ_DIR, 'projects',
                                          generated_project)

  cached_dockerfile = os.path.join(generated_project_folder,
                                   f'Dockerfile_{sanitizer}_cached')
  if os.path.isfile(cached_dockerfile):
    logger.info('Already converted')
    return

  # Check if there is an original Dockerfile, because we should use that in
  # case,as otherwise the "Dockerfile" may be a copy of another sanitizer.
  original_dockerfile = os.path.join(generated_project_folder,
                                     'Dockerfile_original')
  if not os.path.isfile(original_dockerfile):
    dockerfile = os.path.join(generated_project_folder, 'Dockerfile')
    shutil.copy(dockerfile, original_dockerfile)

  with open(original_dockerfile, 'r') as f:
    docker_content = f.read()

  arg_line = 'ARG CACHE_IMAGE=' + cached_image_name
  docker_content = arg_line + '\n' + docker_content
  docker_content = re.sub(r'FROM gcr.io/oss-fuzz-base/base-builder.*',
                          'FROM $CACHE_IMAGE', docker_content)

  # Now comment out everything except:
  # - The first FROM.
  # - The ARG we just added.
  # - The last 2 COPY commands (for the build script and the target we added).
  arg_line = -1
  from_line = -1
  copy_fuzzer_line = -1
  copy_build_line = -1

  for line_idx, line in enumerate(docker_content.split('\n')):
    if line.startswith('ARG') and arg_line == -1:
      arg_line = line_idx
    if line.startswith('FROM') and from_line == -1:
      from_line = line_idx
    if line.startswith('COPY'):
      copy_fuzzer_line = copy_build_line
      copy_build_line = line_idx

  lines_to_keep = {arg_line, from_line, copy_fuzzer_line, copy_build_line}
  new_content = ''
  for line_idx, line in enumerate(docker_content.split('\n')):
    if line_idx not in lines_to_keep:
      new_content += f'# {line}\n'
    else:
      new_content += f'{line}\n'

  # Overwrite the existing one
  with open(cached_dockerfile, 'w') as f:
    f.write(new_content)


def prepare_build(project_name, sanitizer, generated_project):
  """Prepares the correct Dockerfile to be used for cached builds."""
  generated_project_folder = os.path.join(OSS_FUZZ_DIR, 'projects',
                                          generated_project)
  if not ENABLE_CACHING:
    return
  dockerfile_to_use = os.path.join(generated_project_folder, 'Dockerfile')
  original_dockerfile = os.path.join(generated_project_folder,
                                     'Dockerfile_original')
  if is_image_cached(project_name, sanitizer):
    logger.info('Using cached dockerfile')
    cached_dockerfile = os.path.join(generated_project_folder,
                                     f'Dockerfile_{sanitizer}_cached')
    shutil.copy(cached_dockerfile, dockerfile_to_use)
  else:
    logger.info('Using original dockerfile')
    shutil.copy(original_dockerfile, dockerfile_to_use)


def _build_image(project_name: str) -> str:
  """Builds project image in OSS-Fuzz"""
  adjusted_env = os.environ | {
      'FUZZING_LANGUAGE': get_project_language(project_name)
  }
  command = [
      'python3', 'infra/helper.py', 'build_image', '--pull', project_name
  ]
  try:
    sp.run(command,
           cwd=OSS_FUZZ_DIR,
           env=adjusted_env,
           stdout=sp.PIPE,
           stderr=sp.PIPE,
           check=True)
    logger.info('Successfully build project image for %s', project_name)
    return f'gcr.io/oss-fuzz/{project_name}'
  except sp.CalledProcessError as e:
    logger.error('Failed to build project image for %s: %s', project_name,
                 e.stderr.decode('utf-8'))
    return ''


# ===========================================================================
# Library build-cache (LOGICFUZZ_LIB_CACHE). See the module-level flag comment.
# ===========================================================================

# Library-build command verbs that re-run ./configure / make for the *library*.
# Lines starting with these are stripped from the reduced (per-trial) build
# script, because the library is already compiled inside the cached base image.
_LIBCACHE_CONFIGURE_RE = re.compile(
    r'^\s*(\./)?(configure|autogen\.sh|autoreconf|bootstrap|buildconf|'
    r'cmake|meson|automake|aclocal|libtoolize)\b')
_LIBCACHE_MAKE_RE = re.compile(r'^\s*(make|ninja)\b')
_LIBCACHE_FUZZ_TOKEN_RE = re.compile(r'fuzz', re.IGNORECASE)
# A fuzzer-link step that does NOT go through make: ``$CC/$CXX ... $OUT`` or
# ``-o $OUT/...``. Its presence is what makes a build.sh safely reducible.
_LIBCACHE_FUZZER_LINK_RE = re.compile(
    r'\$\{?(CC|CXX)\}?\b.*\$\{?OUT\}?|-o\s+["\']?\$\{?OUT\}?')


def derive_library_cached_build_script(build_sh: str):
  """Transforms a project ``build.sh`` into a reduced script that SKIPS the
  library build (``./configure``/``make``/``cmake``) and only keeps the
  fuzzer-compile + asset-copy steps. Returns the reduced script text, or
  ``None`` when the build.sh cannot be safely reduced (so the caller falls
  back to the full build).

  Conservative by design — only reduces when BOTH hold:
    * there is at least one fuzzer-link step that does not go through ``make``
      (``$CC/$CXX ... $OUT``), proving the fuzzer is built without the library
      make rule; and
    * at least one library-build command was actually found to strip.

  ``make`` lines whose text contains ``fuzz`` are KEPT (some projects build
  the fuzzer via ``make fuzzers``); configure-family lines are always stripped.
  Multi-line continuations (trailing ``\\``) are stripped as a unit.

  Pure function (no Docker/IO) — unit-tested in
  ossfuzz_py/unittests/test_lib_cache_build_script.py.
  """
  if not build_sh or not build_sh.strip():
    return None
  lines = build_sh.split('\n')
  if not any(_LIBCACHE_FUZZER_LINK_RE.search(ln) for ln in lines):
    return None

  out_lines = []
  stripped_any = False
  in_continuation = False
  for ln in lines:
    if in_continuation:
      out_lines.append('# [libcache-skipped] ' + ln)
      in_continuation = ln.rstrip().endswith('\\')
      continue
    is_lib = bool(_LIBCACHE_CONFIGURE_RE.match(ln)) or (
        bool(_LIBCACHE_MAKE_RE.match(ln))
        and not _LIBCACHE_FUZZ_TOKEN_RE.search(ln))
    if is_lib:
      stripped_any = True
      out_lines.append('# [libcache-skipped] ' + ln)
      in_continuation = ln.rstrip().endswith('\\')
    else:
      out_lines.append(ln)

  if not stripped_any:
    return None

  header = (
      '#!/bin/bash -eu\n'
      '# Auto-generated reduced build script (LOGICFUZZ_LIB_CACHE).\n'
      '# Library build commands (configure/make/cmake) are skipped: the\n'
      '# library is already compiled in the cached base image. Only the\n'
      '# fuzz target is recompiled+linked below.\n')
  body = '\n'.join(out_lines)
  # Drop a leading shebang from the original to avoid a duplicate.
  body = re.sub(r'^#!.*\n', '', body, count=1)
  return header + body


def _lib_cache_built_tag(project: str, sanitizer: str) -> str:
  """Local Docker tag of the committed library-prebuilt image."""
  name = rectify_docker_tag(f'{project}-libcache-{sanitizer}-built')
  return f'gcr.io/oss-fuzz/{name}'


def _local_image_exists(tag: str) -> bool:
  """True iff a LOCAL Docker image with ``tag`` exists."""
  try:
    sp.run(['docker', 'image', 'inspect', tag],
           check=True, stdin=sp.DEVNULL,
           stdout=sp.DEVNULL, stderr=sp.STDOUT)
    return True
  except (sp.CalledProcessError, FileNotFoundError):
    return False


def lib_cache_ready(project: str, sanitizer: str) -> bool:
  """True iff a usable library-prebuilt image exists for (project, sanitizer)
  AND a reduced build script was derived for it."""
  if not LIB_CACHE_ENABLED:
    return False
  if (project, sanitizer) not in _LIB_CACHE_READY:
    return False
  return _local_image_exists(_lib_cache_built_tag(project, sanitizer))


def _build_library_cache_for(project: str, language: str,
                             sanitizer: str) -> bool:
  """Builds the project's library ONCE for ``sanitizer`` and commits it to a
  local image, recording the reduced build script. Fail-safe: returns False
  (and records nothing) on any error.
  """
  built_tag = _lib_cache_built_tag(project, sanitizer)
  if _local_image_exists(built_tag):
    # Re-derive the reduced script from the project's build.sh so an
    # already-built image (e.g. from a prior run) is reusable.
    build_sh_path = os.path.join(OSS_FUZZ_DIR, 'projects', project, 'build.sh')
    try:
      with open(build_sh_path) as f:
        reduced = derive_library_cached_build_script(f.read())
    except OSError:
      reduced = None
    if reduced:
      _LIB_CACHE_READY[(project, sanitizer)] = reduced
      logger.info('libcache: reusing existing image %s', built_tag)
      return True
    return False

  # Isolated project copy so we never disturb the trial projects.
  src_project = rectify_docker_tag(f'{project}-libcache-{sanitizer}')
  build_sh_path = os.path.join(OSS_FUZZ_DIR, 'projects', project, 'build.sh')
  try:
    with open(build_sh_path) as f:
      reduced = derive_library_cached_build_script(f.read())
  except OSError as exc:
    logger.warning('libcache: cannot read build.sh for %s: %s', project, exc)
    return False
  if not reduced:
    logger.warning(
        'libcache: build.sh for %s is not safely reducible; skipping cache '
        '(trials will do full builds).', project)
    return False

  # Replicate the project and build its base image (clone + COPY build.sh/*.c).
  try:
    create_ossfuzz_project_by_name(project, src_project)
  except Exception as exc:  # noqa: BLE001 — fail safe
    logger.warning('libcache: failed to replicate %s: %s', project, exc)
    return False
  if not _build_image(src_project):
    logger.warning('libcache: failed to build base image for %s', src_project)
    return False

  # Run the FULL build.sh once (compile the library + original fuzzers) in a
  # NAMED (not --rm) container, then commit the container FS — which holds the
  # compiled library in $SRC — to the cached image.
  container = rectify_docker_tag(f'logicfuzz-libcache-{project}-{sanitizer}')
  outdir = os.path.join(OSS_FUZZ_DIR, 'build', 'out', src_project)
  workdir = os.path.join(OSS_FUZZ_DIR, 'build', 'work', src_project)
  os.makedirs(outdir, exist_ok=True)
  os.makedirs(workdir, exist_ok=True)
  sp.run(['docker', 'rm', '-f', container], stdin=sp.DEVNULL,
         stdout=sp.DEVNULL, stderr=sp.STDOUT, check=False)
  run_cmd = [
      'docker', 'run', '--name', container, '--privileged', '--shm-size=2g',
      '--platform', 'linux/amd64', '-i',
      '-e', 'FUZZING_ENGINE=libfuzzer', '-e', f'SANITIZER={sanitizer}',
      '-e', 'ARCHITECTURE=x86_64', '-e', f'PROJECT_NAME={src_project}',
      '-e', f'FUZZING_LANGUAGE={language}',
      '-v', f'{outdir}:/out', '-v', f'{workdir}:/work',
      '--entrypoint', '/bin/bash', f'gcr.io/oss-fuzz/{src_project}',
      '-c', 'compile',
  ]
  try:
    sp.run(run_cmd, cwd=OSS_FUZZ_DIR, stdin=sp.DEVNULL, check=True)
  except (sp.CalledProcessError, FileNotFoundError) as exc:
    logger.warning('libcache: full build failed for %s/%s: %s', project,
                   sanitizer, exc)
    sp.run(['docker', 'rm', '-f', container], stdin=sp.DEVNULL,
           stdout=sp.DEVNULL, stderr=sp.STDOUT, check=False)
    return False

  try:
    sp.run(['docker', 'commit', container, built_tag], stdin=sp.DEVNULL,
           stdout=sp.DEVNULL, stderr=sp.STDOUT, check=True)
  except sp.CalledProcessError as exc:
    logger.warning('libcache: commit failed for %s/%s: %s', project, sanitizer,
                   exc)
    sp.run(['docker', 'rm', '-f', container], stdin=sp.DEVNULL,
           stdout=sp.DEVNULL, stderr=sp.STDOUT, check=False)
    return False
  sp.run(['docker', 'rm', '-f', container], stdin=sp.DEVNULL,
         stdout=sp.DEVNULL, stderr=sp.STDOUT, check=False)

  _LIB_CACHE_READY[(project, sanitizer)] = reduced
  logger.info('libcache: committed prebuilt library image %s', built_tag)
  return True


def prepare_library_cache(
    experiment_targets: 'list[benchmarklib.Benchmark]') -> None:
  """Serial pre-pass (call BEFORE any trial pool): build each project's library
  once per sanitizer into a committed image. No-op unless LOGICFUZZ_LIB_CACHE=1.
  Always fail-safe — never raises, so a cache miss just means full builds.
  """
  if not LIB_CACHE_ENABLED:
    return
  projects: dict = {}
  for benchmark in experiment_targets:
    projects.setdefault(benchmark.project, benchmark.language)
  logger.info('libcache: preparing library cache for %d project(s)',
              len(projects))
  for project, language in projects.items():
    for sanitizer in ('address', 'coverage'):
      try:
        _build_library_cache_for(project, language, sanitizer)
      except Exception as exc:  # noqa: BLE001 — pre-pass must never break a run
        logger.warning('libcache: unexpected error for %s/%s: %s', project,
                       sanitizer, exc)


def apply_library_cache(project: str, generated_project: str, sanitizer: str,
                        target_path: str) -> bool:
  """Rewrites a trial's generated project to build against the prebuilt library
  image: FROM the committed image, swap in the reduced build script, and keep
  only the driver COPY line(s). Returns True when applied, False to fall back.

  Safe to skip (returns False) when the trial injected its own build script
  (``agent-build.sh``) — we only reduced the project's DEFAULT build.sh.
  """
  reduced = _LIB_CACHE_READY.get((project, sanitizer))
  if not reduced:
    return False
  folder = os.path.join(OSS_FUZZ_DIR, 'projects', generated_project)
  dockerfile = os.path.join(folder, 'Dockerfile')
  if not os.path.isfile(dockerfile):
    return False
  with open(dockerfile) as f:
    content = f.read()
  if 'agent-build.sh' in content:
    # Custom per-trial build script present; our reduction does not apply.
    return False
  # The driver was appended as ``COPY <driver> <target_path>``; keep those.
  driver_copies = [ln for ln in content.split('\n')
                   if ln.startswith('COPY') and target_path in ln]
  if not driver_copies:
    return False

  reduced_name = 'agent-libcache-build.sh'
  try:
    with open(os.path.join(folder, reduced_name), 'w') as f:
      f.write(reduced)
    new_lines = [f'FROM {_lib_cache_built_tag(project, sanitizer)}',
                 f'COPY {reduced_name} /src/build.sh']
    new_lines.extend(driver_copies)
    with open(dockerfile, 'w') as f:
      f.write('\n'.join(new_lines) + '\n')
  except OSError as exc:
    logger.warning('libcache: failed to apply cache for %s: %s',
                   generated_project, exc)
    return False
  logger.info('libcache: trial %s builds against prebuilt %s library',
              generated_project, sanitizer)
  return True


def rectify_docker_tag(docker_tag: str) -> str:
  # Replace "::" and any character not \w, _, or . with "-".
  valid_docker_tag = re.sub(r'::', '-', docker_tag)
  valid_docker_tag = re.sub(r'[^\w_.]', '-', valid_docker_tag)
  # Docker fails with tags containing -_ or _-.
  valid_docker_tag = re.sub(r'[-_]{2,}', '-', valid_docker_tag)
  return valid_docker_tag


def create_ossfuzz_project(benchmark: benchmarklib.Benchmark,
                           generated_oss_fuzz_project: str) -> str:
  """Creates an OSS-Fuzz project by replicating an existing project."""
  generated_project_path = os.path.join(OSS_FUZZ_DIR, 'projects',
                                        generated_oss_fuzz_project)
  if os.path.exists(generated_project_path):
    logger.info('Project %s already exists.', generated_project_path)
    return generated_project_path

  oss_fuzz_project_path = os.path.join(OSS_FUZZ_DIR, 'projects',
                                       benchmark.project)
  shutil.copytree(oss_fuzz_project_path, generated_project_path)
  return generated_project_path


def prepare_project_image(benchmark: benchmarklib.Benchmark,
                          project_name: str = '') -> str:
  """Prepares original image of the |project|'s fuzz target build container."""
  project = benchmark.project
  generated_oss_fuzz_project = project_name or f'{benchmark.id}-{uuid.uuid4().hex}'
  generated_oss_fuzz_project = rectify_docker_tag(generated_oss_fuzz_project)
  image_name = f'gcr.io/oss-fuzz/{generated_oss_fuzz_project}'
  create_ossfuzz_project(benchmark, generated_oss_fuzz_project)

  if not ENABLE_CACHING:
    logger.warning('Disabled caching when building image for %s', project)
  elif is_image_cached(project, 'address'):
    logger.info('Will use cached instance.')
    # Rewrite for caching.
    rewrite_project_to_cached_project(project, generated_oss_fuzz_project,
                                      'address')
    # Prepare build
    prepare_build(project, 'address', generated_oss_fuzz_project)
    # Build the image
    logger.info('Using cached project image for %s: %s',
                generated_oss_fuzz_project, image_name)
  else:
    logger.warning('Unable to find cached project image for %s', project)
  return _build_image(generated_oss_fuzz_project)


def create_ossfuzz_project_by_name(original_name: str,
                                   generated_oss_fuzz_project: str) -> str:
  """Creates an OSS-Fuzz project by replicating an existing project."""
  generated_project_path = os.path.join(OSS_FUZZ_DIR, 'projects',
                                        generated_oss_fuzz_project)
  if os.path.exists(generated_project_path):
    logger.info('Project %s already exists.', generated_project_path)
    return generated_project_path

  oss_fuzz_project_path = os.path.join(OSS_FUZZ_DIR, 'projects', original_name)
  shutil.copytree(oss_fuzz_project_path, generated_project_path)
  return generated_project_path


def prepare_project_image_by_name(project_name: str) -> str:
  """Prepares original image of the |project_name|'s fuzz target build
  container."""
  project = project_name
  image_name = f'gcr.io/oss-fuzz/{project}'
  generated_oss_fuzz_project = f'{project_name}-{uuid.uuid4().hex}'
  generated_oss_fuzz_project = rectify_docker_tag(generated_oss_fuzz_project)
  create_ossfuzz_project_by_name(project, generated_oss_fuzz_project)

  if not ENABLE_CACHING:
    logger.warning('Disabled caching when building image for %s', project)
  elif is_image_cached(project, 'address'):
    logger.info('Will use cached instance.')
    # Rewrite for caching.
    rewrite_project_to_cached_project(project, generated_oss_fuzz_project,
                                      'address')
    # Prepare build
    prepare_build(project, 'address', generated_oss_fuzz_project)
    # Build the image
    logger.info('Using cached project image for %s: %s',
                generated_oss_fuzz_project, image_name)
  else:
    logger.warning('Unable to find cached project image for %s', project)
  return _build_image(generated_oss_fuzz_project)
