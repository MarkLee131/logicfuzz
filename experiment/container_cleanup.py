"""Reliable, SCOPED docker container cleanup for the trial/eval path.

Why this exists
---------------
The OSS-Fuzz trial/eval path starts containers either directly (``docker run``)
or via ``infra/helper.py`` (which adds ``--rm``). Two failure modes leak
containers on a SHARED host:

  1. ``docker run --rm`` does NOT remove the container when the docker-run
     CLIENT process is killed (subprocess ``timeout`` / SIGKILL / parent death):
     the container keeps running under ``dockerd`` and ``--rm`` never fires.
  2. ``docker stop`` (the old timeout cleanup) leaves the container in EXITED
     state — still present, still counted, must be ``docker rm``'d to delete.

Both accumulate until they flood the host and kill long runs mid-aggregation.

The fix
-------
Force-remove (``docker rm -f`` — handles BOTH running and exited) every
container created FROM a given image, scoped by ``ancestor=<image>``. Call it
in a ``finally`` (or via :func:`scoped_project_containers`) around every spawn
so containers are removed on success, timeout, AND exception.

Safety (shared host)
--------------------
The cleanup MUST only ever be handed the uuid-suffixed GENERATED project image
(``gcr.io/oss-fuzz/<project>-<uuid>``) — never a bare base image like
``gcr.io/oss-fuzz/lcms`` (which may back a user's interactive shell). The
generated name is built as ``f'{id}-{uuid4().hex}'`` and ``rectify_docker_tag``
preserves the hex, so the uuid is always present. As defense-in-depth,
:func:`force_remove_project_containers` REFUSES any image that does not look
uuid-scoped, so a mistaken bare-base argument is inert.
"""
from __future__ import annotations

import contextlib
import logging
import re
import shutil
import subprocess as sp
import uuid

logger = logging.getLogger(__name__)

# A generated project image carries a >=8-char hex run from uuid4().hex
# (e.g. ``lcms-ab12cd34...``). A bare base image (``lcms``) does not, so it is
# refused — the keystone safety guard for the shared host.
_UUID_SCOPED = re.compile(r"[-_][0-9a-f]{8,}")


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def looks_uuid_scoped(image: str) -> bool:
    """True iff ``image`` carries a uuid-like hex suffix (a GENERATED project
    image), so ``ancestor=``-scoped cleanup cannot match a bare base image."""
    return bool(image) and bool(_UUID_SCOPED.search(image))


def force_remove_project_containers(image: str, *, timeout: int = 30) -> int:
    """``docker rm -f`` every container created FROM ``image`` (running OR
    exited), scoped by ``ancestor=<image>``.

    ``image`` MUST be a uuid-suffixed generated project image — a bare base
    image is REFUSED (returns 0, issues no docker command). Best-effort:
    swallows every error and never raises. Returns the number of containers
    for which a remove was attempted.
    """
    if not image or not _docker_available():
        return 0
    if not looks_uuid_scoped(image):
        logger.warning(
            "container cleanup REFUSED for un-scoped image %r (not uuid-"
            "suffixed) — refusing to risk a shared base/interactive container",
            image,
        )
        return 0
    try:
        result = sp.run(
            ["docker", "ps", "-aq", "--filter", f"ancestor={image}"],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except Exception as exc:  # noqa: BLE001 — cleanup must never raise
        logger.debug("container cleanup list failed for %s: %s", image, exc)
        return 0
    ids = [c for c in (result.stdout or "").split() if c]
    n = 0
    for cid in ids:
        try:
            sp.run(["docker", "rm", "-f", cid], capture_output=True,
                   text=True, timeout=timeout, check=False)
            n += 1
        except Exception as exc:  # noqa: BLE001
            logger.debug("docker rm -f %s failed: %s", cid, exc)
            return 0  # a hang/timeout here: stop, never raise
    if n:
        logger.info("cleaned up %d leaked container(s) for %s", n, image)
    return n


@contextlib.contextmanager
def scoped_project_containers(image: str, *, timeout: int = 30):
    """Context manager: force-remove ``image``'s containers in ``finally`` —
    fires on success, exception, AND (because it is a finally) on a handled
    timeout. Best-effort; never raises from cleanup."""
    try:
        yield
    finally:
        try:
            force_remove_project_containers(image, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 — defensive; util already safe
            logger.debug("scoped container cleanup failed for %s: %s",
                         image, exc)


# --- name-based cleanup -------------------------------------------------------
# For containers run on a SHARED/base image (gcr.io/oss-fuzz-base/base-runner or
# the bare gcr.io/oss-fuzz/<project>), ancestor-scoping is UNSAFE — it would
# match a concurrent run's (or a user's interactive) container on the same base
# image. Instead, give such a container a UNIQUE ``--name`` (via
# :func:`make_container_name`) and remove it by that exact name.

def make_container_name(prefix: str) -> str:
    """A unique, uuid-scoped container name (``lf-<prefix>-<hex16>``) safe to
    pass to ``docker run --name`` and to :func:`force_remove_named_container`."""
    return f"lf-{prefix}-{uuid.uuid4().hex[:16]}"


def force_remove_named_container(name: str, *, timeout: int = 30) -> int:
    """``docker rm -f <name>`` (running OR exited; no-op if absent). For a
    container we launched with a unique ``--name``. Best-effort: swallows every
    error and never raises. Returns 1 if a remove was attempted, else 0."""
    if not name or not _docker_available():
        return 0
    try:
        sp.run(["docker", "rm", "-f", name], capture_output=True, text=True,
               timeout=timeout, check=False)
        return 1
    except Exception as exc:  # noqa: BLE001 — cleanup must never raise
        logger.debug("docker rm -f %s failed: %s", name, exc)
        return 0


@contextlib.contextmanager
def scoped_named_container(name: str, *, timeout: int = 30):
    """Context manager: ``docker rm -f <name>`` in ``finally`` — fires on
    success, exception, and handled timeout. Best-effort; never raises."""
    try:
        yield
    finally:
        try:
            force_remove_named_container(name, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 — defensive; util already safe
            logger.debug("scoped named cleanup failed for %s: %s", name, exc)
