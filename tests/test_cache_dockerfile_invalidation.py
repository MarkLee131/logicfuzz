"""Keystone build bug (2026-06-16, systematic-debugging): cached-build projects
(lcms, c-ares) compiled the STOCK fuzzer, not the generated driver. Root cause:
the extraction phase snapshots Dockerfile_original + Dockerfile_<san>_cached BEFORE
the driver is injected; the trial build's rewrite then hits the 'Already converted'
early-return and reuses the stale, driver-less cached Dockerfile (verified via
timestamps: Dockerfile_original @13:38 vs driver @13:42). Fix: after the driver
COPY is appended, invalidate the stale cache Dockerfiles so the rewrite regenerates
them from the driver-injected Dockerfile (where the appended `COPY <driver>
<target_path>` is the last COPY → kept by the 'last 2 COPYs' rewrite, for BOTH the
lcms `COPY *.c` and the c-ares repo-path structures).
"""
import os
import tempfile

from experiment.oss_fuzz_checkout import _invalidate_stale_cache_dockerfiles


def _mk_project():
    d = tempfile.mkdtemp(prefix='proj_')
    for name in ('Dockerfile', 'Dockerfile_original',
                 'Dockerfile_address_cached', 'Dockerfile_coverage_cached'):
        with open(os.path.join(d, name), 'w') as f:
            f.write('stale\n')
    return d


def test_removes_stale_original_and_cached():
    d = _mk_project()
    _invalidate_stale_cache_dockerfiles(d)
    assert not os.path.exists(os.path.join(d, 'Dockerfile_original'))
    assert not os.path.exists(os.path.join(d, 'Dockerfile_address_cached'))
    assert not os.path.exists(os.path.join(d, 'Dockerfile_coverage_cached'))


def test_keeps_the_live_dockerfile():
    # The live Dockerfile (with the appended driver COPY) MUST survive — it's the
    # rewrite's fresh source.
    d = _mk_project()
    _invalidate_stale_cache_dockerfiles(d)
    assert os.path.exists(os.path.join(d, 'Dockerfile'))


def test_idempotent_on_clean_dir():
    d = tempfile.mkdtemp(prefix='clean_')
    open(os.path.join(d, 'Dockerfile'), 'w').close()
    _invalidate_stale_cache_dockerfiles(d)  # no stale files → no error
    assert os.path.exists(os.path.join(d, 'Dockerfile'))
