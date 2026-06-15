"""Reliable, SCOPED docker container cleanup for the trial/eval path.

The leak: `docker run --rm` does NOT remove the container when the docker-run
CLIENT is killed (subprocess timeout / SIGKILL / parent death) — the container
keeps running under dockerd and --rm never fires; and `docker stop` leaves the
container EXITED. On a shared host these accumulate and flood it.

The fix utility force-removes (`docker rm -f`, both running + exited) every
container created FROM a given image, scoped by `ancestor=<image>`. Safety: it
MUST only ever be handed the uuid-suffixed GENERATED project image
(gcr.io/oss-fuzz/<project>-<uuid>), never a bare base image like
gcr.io/oss-fuzz/lcms (a user's interactive shell). A defense-in-depth guard
refuses any image that doesn't look uuid-scoped.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from experiment import container_cleanup as cc  # noqa: E402


class _Rec:
    """Records subprocess.run calls and returns a scripted stdout."""

    def __init__(self, ps_stdout="", raise_on=None):
        self.calls = []
        self._ps_stdout = ps_stdout
        self._raise_on = raise_on or ()

    def run(self, cmd, *a, **k):
        self.calls.append(list(cmd))
        if any(tok in cmd for tok in self._raise_on):
            raise RuntimeError("boom")

        class R:
            pass

        r = R()
        # `docker ps -aq ...` returns the id list; everything else empty.
        r.stdout = self._ps_stdout if ("ps" in cmd) else ""
        r.returncode = 0
        return r


GEN = "gcr.io/oss-fuzz/lcms-ab12cd34ef5678901234567890abcdef"
BASE = "gcr.io/oss-fuzz/lcms"


def _wire(monkeypatch, rec, docker=True):
    monkeypatch.setattr(cc.sp, "run", rec.run)
    monkeypatch.setattr(cc.shutil, "which",
                        lambda _x: "/usr/bin/docker" if docker else None)


def test_force_remove_lists_by_ancestor_then_rm_f(monkeypatch):
    rec = _Rec(ps_stdout="cid1\ncid2\n")
    _wire(monkeypatch, rec)
    n = cc.force_remove_project_containers(GEN)
    assert n == 2
    # first call lists by ancestor=<generated image>, -a (incl. exited), -q
    ps = rec.calls[0]
    assert ps[:3] == ["docker", "ps", "-aq"]
    assert f"ancestor={GEN}" in ps
    # then one `docker rm -f <cid>` per id
    rms = [c for c in rec.calls if c[:3] == ["docker", "rm", "-f"]]
    assert [c[3] for c in rms] == ["cid1", "cid2"], rec.calls


def test_force_remove_refuses_unscoped_base_image(monkeypatch):
    rec = _Rec(ps_stdout="cidX\n")
    _wire(monkeypatch, rec)
    n = cc.force_remove_project_containers(BASE)
    assert n == 0
    # SAFETY: no docker command issued at all for a bare base image
    assert rec.calls == [], rec.calls


def test_force_remove_noop_when_docker_absent(monkeypatch):
    rec = _Rec(ps_stdout="cid1\n")
    _wire(monkeypatch, rec, docker=False)
    assert cc.force_remove_project_containers(GEN) == 0
    assert rec.calls == []


def test_force_remove_noop_on_empty_image(monkeypatch):
    rec = _Rec()
    _wire(monkeypatch, rec)
    assert cc.force_remove_project_containers("") == 0
    assert rec.calls == []


def test_force_remove_swallows_list_errors(monkeypatch):
    rec = _Rec(ps_stdout="cid1\n", raise_on=("ps",))
    _wire(monkeypatch, rec)
    # must never raise even if `docker ps` blows up
    assert cc.force_remove_project_containers(GEN) == 0


def test_force_remove_swallows_rm_errors(monkeypatch):
    rec = _Rec(ps_stdout="cid1\ncid2\n", raise_on=("rm",))
    _wire(monkeypatch, rec)
    # rm failures are swallowed; returns 0 removed but does not raise
    assert cc.force_remove_project_containers(GEN) == 0


def test_scoped_context_manager_cleans_on_exception(monkeypatch):
    rec = _Rec(ps_stdout="cid1\n")
    _wire(monkeypatch, rec)
    try:
        with cc.scoped_project_containers(GEN):
            raise ValueError("trial blew up")
    except ValueError:
        pass
    # cleanup still fired in finally
    assert any(c[:3] == ["docker", "rm", "-f"] for c in rec.calls), rec.calls


def test_scoped_context_manager_cleans_on_success(monkeypatch):
    rec = _Rec(ps_stdout="cid1\n")
    _wire(monkeypatch, rec)
    with cc.scoped_project_containers(GEN):
        pass
    assert any(c[:3] == ["docker", "rm", "-f"] for c in rec.calls), rec.calls


# ---- name-based cleanup: for containers run on a SHARED/base image
# (gcr.io/oss-fuzz-base/base-runner, gcr.io/oss-fuzz/<project>) where ancestor-
# scoping is unsafe; we give the container a unique --name and remove by name --

def test_force_remove_named_issues_rm_f_by_name(monkeypatch):
    rec = _Rec()
    _wire(monkeypatch, rec)
    n = cc.force_remove_named_container("lf-preflight-abc1234567890def")
    assert n == 1
    assert rec.calls == [
        ["docker", "rm", "-f", "lf-preflight-abc1234567890def"]], rec.calls


def test_force_remove_named_noop_empty(monkeypatch):
    rec = _Rec()
    _wire(monkeypatch, rec)
    assert cc.force_remove_named_container("") == 0
    assert rec.calls == []


def test_force_remove_named_noop_no_docker(monkeypatch):
    rec = _Rec()
    _wire(monkeypatch, rec, docker=False)
    assert cc.force_remove_named_container("lf-x-1") == 0
    assert rec.calls == []


def test_force_remove_named_swallows_errors(monkeypatch):
    rec = _Rec(raise_on=("rm",))
    _wire(monkeypatch, rec)
    assert cc.force_remove_named_container("lf-x-1") == 0  # swallowed, no raise


def test_scoped_named_cleans_on_exception(monkeypatch):
    rec = _Rec()
    _wire(monkeypatch, rec)
    try:
        with cc.scoped_named_container("lf-x-1"):
            raise ValueError("boom")
    except ValueError:
        pass
    assert ["docker", "rm", "-f", "lf-x-1"] in rec.calls, rec.calls


def test_make_container_name_unique_and_prefixed():
    a = cc.make_container_name("preflight")
    b = cc.make_container_name("preflight")
    assert a != b
    assert a.startswith("lf-preflight-")
    # always uuid-scoped so it can never collide with a base/interactive name
    assert cc.looks_uuid_scoped(a)


# ---- label-based cleanup: for container_tool's shared `-d` agent shells, which
# share the bare base image with a user's interactive shell — so they MUST be
# swept by a label WE set, never by image/ancestor --------------------------

def test_force_remove_labeled_lists_by_label_then_rm_f(monkeypatch):
    rec = _Rec(ps_stdout="cidA\ncidB\n")
    _wire(monkeypatch, rec)
    n = cc.force_remove_labeled_containers("logicfuzz-run=abc123")
    assert n == 2
    ps = rec.calls[0]
    assert ps[:3] == ["docker", "ps", "-aq"]
    assert "label=logicfuzz-run=abc123" in ps
    rms = [c for c in rec.calls if c[:3] == ["docker", "rm", "-f"]]
    assert [c[3] for c in rms] == ["cidA", "cidB"], rec.calls


def test_force_remove_labeled_refuses_empty_label(monkeypatch):
    # SAFETY: an empty/bare label could match unrelated containers — refuse.
    rec = _Rec(ps_stdout="cidX\n")
    _wire(monkeypatch, rec)
    assert cc.force_remove_labeled_containers("") == 0
    assert rec.calls == []


def test_force_remove_labeled_noop_no_docker(monkeypatch):
    rec = _Rec(ps_stdout="cidA\n")
    _wire(monkeypatch, rec, docker=False)
    assert cc.force_remove_labeled_containers("logicfuzz-run=x") == 0
    assert rec.calls == []


def test_force_remove_labeled_swallows_errors(monkeypatch):
    rec = _Rec(ps_stdout="cidA\n", raise_on=("ps",))
    _wire(monkeypatch, rec)
    assert cc.force_remove_labeled_containers("logicfuzz-run=x") == 0
