"""A tool for LLM agents to interact within a project's docker container."""
import atexit
import logging
import os
import subprocess as sp
import threading
import uuid
from typing import Dict, Tuple

from experiment import container_cleanup, oss_fuzz_checkout
from experiment.benchmark import Benchmark
from tool.base_tool import BaseTool

logger = logging.getLogger(__name__)

# Per-RUN id shared across the main process AND its forked Pool workers (set in
# the env at run_logicfuzz startup, BEFORE the Pool fork, so every worker
# inherits the same value). Agent containers are labelled with it so a run-end
# sweep can reclaim worker-orphaned shells (whose in-memory IDs the main
# process never saw) WITHOUT touching a concurrent run's containers (different
# id) or a user's interactive shell (no label). Fallback uuid keeps it working
# when launched outside run_logicfuzz.
_RUN_ID = os.environ.get('LOGICFUZZ_RUN_ID') or uuid.uuid4().hex[:16]
_AGENT_LABEL = 'logicfuzz-agent=1'
_RUN_LABEL = f'logicfuzz-run={_RUN_ID}'

# Container reuse: keep one long-lived `docker run -d` per (image_name,
# language) pair across all ProjectContainerTool instances. Each tool
# call goes through `docker exec` against the shared container, saving
# 1-2s per call (container startup) and avoiding repeated apt cache
# warm-up for tools that re-enter the same project image.
#
# Disable with LIBERATOR_DISABLE_CONTAINER_REUSE=1 (e.g. if isolation
# matters for a debug repro).
_DISABLE_REUSE = bool(int(os.environ.get('LIBERATOR_DISABLE_CONTAINER_REUSE',
                                          '0')))

# (image_name, language) -> (container_id, refcount)
_SHARED_CONTAINERS: Dict[Tuple[str, str], Tuple[str, int]] = {}
_SHARED_CONTAINERS_LOCK = threading.Lock()


def _docker_stop_and_remove(container_id: str) -> bool:
  """Stops then removes a container so it doesn't linger as an Exited shell.

  `docker stop` is synchronous (it waits for the container to halt, sending
  SIGKILL after a grace period), so the subsequent `docker rm` reliably
  succeeds. Returns True if the container is gone afterwards.
  """
  if not container_id:
    return True
  sp.run(['docker', 'stop', container_id], stdout=sp.PIPE, stderr=sp.PIPE,
         check=False)
  result = sp.run(['docker', 'rm', container_id], stdout=sp.PIPE,
                  stderr=sp.PIPE, check=False)
  return result.returncode == 0


def _cleanup_shared_containers() -> None:
  """atexit hook: stop+remove any shared containers still alive at exit.

  Covers paths where `terminate()` wasn't called on every tool (e.g. an
  unhandled exception or an early sys.exit). This does NOT run on SIGKILL
  (`kill -9`); those leak and are reclaimed by a manual prune.
  """
  with _SHARED_CONTAINERS_LOCK:
    targets = [(key[0], cid) for key, (cid, _) in _SHARED_CONTAINERS.items()]
    _SHARED_CONTAINERS.clear()
  for image_name, cid in targets:
    try:
      _docker_stop_and_remove(cid)
      logger.debug('atexit: removed shared container %s for %s', cid[:12],
                   image_name)
    except Exception as e:  # pylint: disable=broad-except
      logger.debug('atexit: failed to remove container %s: %s', cid, e)
  # Belt-and-suspenders: sweep any agent shell carrying THIS run's label that
  # the in-memory map missed — e.g. created in a forked Pool worker that was
  # recycled (maxtasksperchild=1) before its own atexit could run, the exact
  # leak observed on the lcms A/B. Label-scoped to this run, so it never touches
  # a concurrent run's shells or a user's unlabelled interactive container.
  try:
    container_cleanup.force_remove_labeled_containers(_RUN_LABEL)
  except Exception as e:  # pylint: disable=broad-except
    logger.debug('atexit: label sweep failed: %s', e)


atexit.register(_cleanup_shared_containers)


class ProjectContainerTool(BaseTool):
  """A tool for LLM agents to interact within a project's docker container."""

  def __init__(self,
               benchmark: Benchmark,
               name: str = '',
               project_name: str = '',
               use_llvm14_builder: bool = False) -> None:
    super().__init__(benchmark, name)
    self.project_name = project_name or benchmark.project
    # A1: clang-14 is baked into the canonical base-builder (additive), so the
    # *normal* project image already supports bitcode extraction — no separate
    # extraction image/tag is needed. use_llvm14_builder only ensures the base is
    # augmented (idempotent) inside prepare_project_image.
    self.image_name = self._prepare_project_image(
        self.project_name, use_llvm14_builder=use_llvm14_builder)
    self.container_id, self._container_is_shared = (
        self._acquire_container())
    self.build_script_path = '/src/build.sh'
    self._backup_default_build_script()
    self.project_dir = self._get_project_dir()

  def _acquire_container(self) -> Tuple[str, bool]:
    """Get a running container for this image. Returns (id, is_shared).

    On reuse the caller must NOT terminate the container in their own
    `terminate()` — the refcounted teardown lives here.
    """
    if _DISABLE_REUSE:
      return self._start_docker_container(), False

    key = (self.image_name, self.benchmark.language)
    with _SHARED_CONTAINERS_LOCK:
      entry = _SHARED_CONTAINERS.get(key)
      if entry is not None:
        cid, refs = entry
        # Verify it's still running — docker may have garbage-collected
        # if a parent process died unexpectedly.
        check = sp.run(['docker', 'inspect', '-f', '{{.State.Running}}', cid],
                       stdout=sp.PIPE, stderr=sp.PIPE, text=True)
        if check.returncode == 0 and check.stdout.strip() == 'true':
          _SHARED_CONTAINERS[key] = (cid, refs + 1)
          logger.debug('Reusing container %s for %s (refs=%d)',
                       cid[:12], self.image_name, refs + 1)
          return cid, True
        # Stale entry — clear and restart.
        logger.debug('Stale shared container %s for %s; restarting',
                     cid[:12], self.image_name)
        _SHARED_CONTAINERS.pop(key, None)
      cid = self._start_docker_container()
      if cid:
        _SHARED_CONTAINERS[key] = (cid, 1)
      return cid, True

  def tutorial(self) -> str:
    """Constructs a tool guide tutorial for LLM agents."""
    return self._get_tutorial_file_content('container_tool.txt').replace(
        '{FUZZ_TARGET_PATH}', self.benchmark.target_path)

  def _prepare_project_image(self, project_name: str,
                              use_llvm14_builder: bool = False) -> str:
    """Prepares the project's OSS-Fuzz docker image and returns the image name.
    """
    image_name = oss_fuzz_checkout.prepare_project_image(
        self.benchmark, project_name, use_llvm14_builder=use_llvm14_builder)
    if image_name:
      return image_name
    raise Exception(f'Failed to build image for {project_name}')

  def _execute_command_in_container(self,
                                    command: list[str],
                                    timeout: int = 60) -> sp.CompletedProcess:
    """Executes the |command| in subprocess and log output."""
    try:
      result = sp.run(command,
                      stdout=sp.PIPE,
                      stderr=sp.PIPE,
                      check=False,
                      text=True,
                      encoding='utf-8',
                      errors='ignore',
                      timeout=timeout)

      logger.debug(
          'Executing command (%s) in container %s: Return code %d. STDOUT: %s, '
          'STDERR: %s', command, self.container_id, result.returncode,
          result.stdout, result.stderr)
      return result
    except sp.TimeoutExpired:
      logger.warning('Command timed out after %ds: %s', timeout, command)
      return sp.CompletedProcess(command, returncode=124, stdout='',
                                  stderr=f'Command timed out after {timeout}s')
    except Exception as e:
      logger.error(
          'Executing command (%s) in container failed with Exception: %s',
          command, e)
      return sp.CompletedProcess(command, returncode=1, stdout='', stderr='')

  def _execute_command(self, command: list[str]) -> sp.CompletedProcess:
    """Executes the |command| in subprocess and log output."""
    try:
      result = sp.run(command,
                      stdout=sp.PIPE,
                      stderr=sp.PIPE,
                      check=False,
                      text=True,
                      encoding='utf-8',
                      errors='ignore')

      logger.debug(
          'Executing command (%s): Return code %d. STDOUT: %s, STDERR: %s',
          command, result.returncode, result.stdout, result.stderr)
      return result
    except Exception as e:
      logger.error('Executing command (%s) failed with Exception: %s', command,
                   e)
      return sp.CompletedProcess(command, returncode=1, stdout='', stderr='')

  def _backup_default_build_script(self) -> None:
    """Creates a copy of the human-written /src/build.sh for LLM to use."""
    backup_command = f'cp {self.build_script_path} /src/build.bk.sh'
    process = self.execute(backup_command)
    if process.returncode:
      logger.error('Failed to create a backup of %s: %s',
                   self.build_script_path, self.image_name)

  def _get_project_dir(self) -> str:
    """Returns the project-under-test's source code directory."""
    pwd_command = 'pwd'
    process = self.execute(pwd_command)
    if process.returncode:
      logger.error('Failed to get the WORKDIR: %s', self.image_name)
      return ''
    return process.stdout.strip()

  def _start_docker_container(self) -> str:
    """Runs the project's OSS-Fuzz image as a background container and returns
    the container ID."""
    run_container_command = [
        'docker', 'run', '-d', '-t',
        # Leak-prevention: a unique name + our labels so this shell is safely
        # distinguishable from a user's (unlabelled) interactive container and
        # reclaimable by the run-end label sweep. See _cleanup_shared_containers.
        '--name', container_cleanup.make_container_name('agent'),
        '--label', _AGENT_LABEL, '--label', _RUN_LABEL,
        '--entrypoint=/bin/bash', '-e',
        f'FUZZING_LANGUAGE={self.benchmark.language}', self.image_name
    ]
    result = self._execute_command(run_container_command)
    if result.returncode:
      logger.error('Failed to start container of image: %s', self.image_name)
    container_id = result.stdout.strip()
    return container_id

  def execute(self, command: str, timeout: int = 60) -> sp.CompletedProcess:
    """Executes the |command| in the container and returns the output."""
    logger.debug('Executing command (%s) in %s: ', command, self.container_id)
    execute_command_in_container = [
        'docker', 'exec', self.container_id, '/bin/bash', '-c', command
    ]
    process = self._execute_command_in_container(execute_command_in_container,
                                                  timeout=timeout)
    process.args = command
    return process

  def compile(self, extra_commands: str = '',
              timeout: int = 300) -> sp.CompletedProcess:
    """Compiles the fuzz target."""
    command = 'compile > /dev/null' + extra_commands
    compile_process = self.execute(command, timeout=timeout)
    # Hide Compilation command so that LLM won't reuse it in the inspection tool
    # and be distracted by irrelevant errors, e.g., `build/ already exits`.
    compile_process.args = '# Compiles the fuzz target.'
    return compile_process

  def terminate(self) -> bool:
    """Terminates the container.

    For shared containers, just decrements the refcount. The container
    is only stopped+removed when the last user releases it.
    """
    if self._container_is_shared and not _DISABLE_REUSE:
      key = (self.image_name, self.benchmark.language)
      with _SHARED_CONTAINERS_LOCK:
        entry = _SHARED_CONTAINERS.get(key)
        if entry is None:
          return True  # Already torn down by another path.
        cid, refs = entry
        if cid != self.container_id:
          # Someone else (re)started it; we no longer own the slot.
          return True
        new_refs = refs - 1
        if new_refs > 0:
          _SHARED_CONTAINERS[key] = (cid, new_refs)
          logger.debug('Released container %s for %s (refs=%d)',
                       cid[:12], self.image_name, new_refs)
          return True
        _SHARED_CONTAINERS.pop(key, None)
    # Last user (or non-shared mode) — stop AND remove so the container
    # doesn't linger as an Exited shell (the source of container pile-up).
    return _docker_stop_and_remove(self.container_id)

  def write_to_file(self, content: str, file_path: str) -> None:
    replace_file_content_command = (
        f'cat << "OFG_EOF" > {file_path}\n{content}\nOFG_EOF')
    self.execute(replace_file_content_command)
