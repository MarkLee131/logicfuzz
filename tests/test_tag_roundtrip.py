"""cmstypes.c (tag (de)serializers) is the single biggest untapped lcms block
(95/2270 = 4%). Its WRITE handlers fire only on cmsSaveProfileToMem of a tag-rich
profile; its READ handlers only on cmsReadTag of a SAVED+REOPENED profile (an
in-memory profile returns the live object without deserializing). No generated
driver did this round-trip. LOGICFUZZ_TAG_ROUNDTRIP appends a guarded
save->reopen->read block on any cmsHPROFILE-producing skeleton. These tests pin
the emitter (fires on profile handles, not on non-profile chains; gate-off inert).
"""
import os
import importlib

import liberator_adapter.driver.synthesis.skeleton_generator as sg


def _profile_skeleton():
    sk = sg.DriverSkeleton(name='t', target_apis=[])
    sk.variables['ret_cmsCreate_sRGBProfile'] = sg.SkeletonVariable(
        name='ret_cmsCreate_sRGBProfile', c_type='cmsHPROFILE',
        source_api='cmsCreate_sRGBProfile')
    return sk


def _non_profile_skeleton():
    sk = sg.DriverSkeleton(name='t', target_apis=[])
    sk.variables['ret_cmsBuildGamma'] = sg.SkeletonVariable(
        name='ret_cmsBuildGamma', c_type='cmsToneCurve *',
        source_api='cmsBuildGamma')
    return sk


def _emit(sk):
    gen = sg.SkeletonGenerator()
    gen._append_tag_roundtrip(sk)
    return "\n".join(s.code for s in sk.statements)


def test_gate_on_emits_roundtrip_on_profile(monkeypatch):
    monkeypatch.setenv('LOGICFUZZ_TAG_ROUNDTRIP', '1')
    code = _emit(_profile_skeleton())
    assert 'cmsSaveProfileToMem' in code      # write handlers
    assert 'cmsOpenProfileFromMem' in code    # reopen
    assert 'cmsReadTag' in code               # read handlers
    assert 'ret_cmsCreate_sRGBProfile' in code  # exercises THIS profile


def test_gate_off_inert(monkeypatch):
    monkeypatch.delenv('LOGICFUZZ_TAG_ROUNDTRIP', raising=False)
    assert _emit(_profile_skeleton()) == ""


def test_non_profile_not_touched(monkeypatch):
    monkeypatch.setenv('LOGICFUZZ_TAG_ROUNDTRIP', '1')
    assert _emit(_non_profile_skeleton()) == ""
