import os
import re
import stat
import subprocess
import sys

import pytest

import tau_engine_profile as profile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPECTED_DIGEST = "143b054f805eea19d21a35083a31572529632d06ae6bb31f17cb75d21ba893f2"


def _fake_tool(directory, name):
    path = os.path.join(str(directory), name)
    with open(path, "w") as fh:
        fh.write("#!/bin/sh\nexit 0\n")
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)


class _Result:
    def __init__(self, value):
        self.value = value


class FakeModule:
    def __init__(self, names=None, masked=None):
        self.options = {k: "initial" for k in (names or profile.MANIFEST)}
        self.masked = masked or {}
        self.writes = []

    def option_names(self):
        return list(self.options)

    def set_option(self, name, text):
        self.writes.append((name, text))
        self.options[name] = text
        return _Result(text)

    def get_option(self, name):
        if name in self.masked:
            return _Result(self.masked[name])
        value = self.options[name]
        if name == "nlang-api-key":
            return _Result("set" if value else "unset")
        return _Result(value)


@pytest.fixture(autouse=True)
def _no_spot_locations(monkeypatch):
    monkeypatch.setattr(profile, "_package_spot_dirs", lambda: [])


def test_option_env_name_mapping():
    assert profile.option_env_name("max-revision-alts") == "TAU_MAX_REVISION_ALTS"
    assert profile.option_env_name("spot-bin") == "TAU_SPOT_BIN"


def test_environment_table():
    env = {
        "TAU_OUTPUT_PREFER": "x",
        "TAU_MAX_REVISION_ALTS": "5",
        "TAU_SPOT_BIN": "/somewhere",
        "TAU_NLANG_API_KEY": "k",
        "OPENAI_API_KEY": "k1",
        "ANTHROPIC_API_KEY": "k2",
        "TAU_NETWORK_ID": "net",
        "TAU_FORCE_TEST": "0",
        "TAU_MAX_MEMPOOL_TXS": "10",
        "HOME": "/home/x",
        "PYTHONPATH": "/p",
        "DYLD_LIBRARY_PATH": "/d",
    }
    profile.prepare_environment(env)
    assert env == {
        "TAU_NETWORK_ID": "net",
        "TAU_FORCE_TEST": "0",
        "TAU_MAX_MEMPOOL_TXS": "10",
        "HOME": "/home/x",
        "PYTHONPATH": "/p",
        "DYLD_LIBRARY_PATH": "/d",
    }


def test_every_option_variable_is_dropped():
    env = {profile.option_env_name(o): "1" for o in profile.MANIFEST}
    profile.prepare_environment(env)
    assert env == {}


def test_path_scrub_drops_tool_dirs_and_keeps_order(tmp_path, caplog):
    bad = []
    for name in ("ltlsynt", "autfilt", "ltlfilt"):
        d = tmp_path / ("has_" + name)
        d.mkdir()
        _fake_tool(d, name)
        bad.append(str(d))
    good_a, good_b = tmp_path / "a", tmp_path / "b"
    good_a.mkdir()
    good_b.mkdir()
    entries = [str(good_a), bad[0], str(good_b), bad[1], bad[2]]
    env = {"PATH": os.pathsep.join(entries)}
    with caplog.at_level("WARNING"):
        dropped = profile.prepare_environment(env)
    assert dropped == bad
    assert env["PATH"] == os.pathsep.join([str(good_a), str(good_b)])
    for entry in bad:
        assert entry in caplog.text


def test_path_without_tools_is_untouched(tmp_path):
    original = os.pathsep.join([str(tmp_path), "/nonexistent-dir"])
    env = {"PATH": original}
    assert profile.prepare_environment(env) == []
    assert env["PATH"] == original


def test_path_removed_when_every_entry_dropped(tmp_path):
    _fake_tool(tmp_path, "ltlsynt")
    env = {"PATH": str(tmp_path)}
    profile.prepare_environment(env)
    assert "PATH" not in env


def test_node_variables_do_not_collide_with_option_variables():
    option_vars = {profile.option_env_name(o) for o in profile.MANIFEST}
    used = set()
    for root, dirs, files in os.walk(REPO_ROOT):
        dirs[:] = [d for d in dirs
                   if d not in {"tests", "venv", ".git", "node_modules", "data", "data_local"}
                   and not d.startswith(".")]
        for fname in files:
            if not fname.endswith(".py") or fname.startswith("test_"):
                continue
            with open(os.path.join(root, fname), encoding="utf-8") as fh:
                used.update(re.findall(r"TAU_[A-Z0-9_]+", fh.read()))
    assert used
    assert not used & option_vars, sorted(used & option_vars)


def test_apply_sets_every_option():
    module = FakeModule()
    profile.apply(module, environ={"PATH": "/nonexistent-dir"})
    written = dict(module.writes)
    assert set(written) == set(profile.MANIFEST)
    assert written["nlang-api-key"] == ""
    assert written["ltl-timeout"] == "60"
    assert written["max-revision-alts"] == "0"


def test_apply_rejects_extra_option():
    module = FakeModule(names=list(profile.MANIFEST) + ["new-option"])
    with pytest.raises(profile.EngineProfileError, match="new-option"):
        profile.apply(module, environ={})


def test_apply_rejects_missing_option():
    names = [o for o in profile.MANIFEST if o != "ltl-timeout"]
    with pytest.raises(profile.EngineProfileError, match="ltl-timeout"):
        profile.apply(FakeModule(names=names), environ={})


def test_apply_rejects_read_back_mismatch():
    module = FakeModule(masked={"bv-solve-timeout": "5"})
    with pytest.raises(profile.EngineProfileError, match="bv-solve-timeout"):
        profile.apply(module, environ={"PATH": "/nonexistent-dir"})


def test_apply_rejects_package_directory_tool(tmp_path, monkeypatch):
    _fake_tool(tmp_path, "autfilt")
    monkeypatch.setattr(profile, "_package_spot_dirs", lambda: [str(tmp_path)])
    with pytest.raises(profile.EngineProfileError, match=re.escape(str(tmp_path))):
        profile.apply(FakeModule(), environ={"PATH": "/nonexistent-dir"})


def test_apply_rejects_tool_left_on_path(tmp_path):
    _fake_tool(tmp_path, "ltlfilt")
    with pytest.raises(profile.EngineProfileError):
        profile.apply(FakeModule(), environ={"PATH": str(tmp_path)})


def test_package_dirs_derive_from_executable(monkeypatch):
    monkeypatch.undo()
    dirs = profile._package_spot_dirs()
    exe_dir = os.path.dirname(sys.executable)
    assert os.path.join(exe_dir, "libexec", "tau", "spot") in dirs


def test_digest_is_stable():
    assert profile.manifest_digest() == EXPECTED_DIGEST
    assert profile.manifest_digest(dict(reversed(list(profile.MANIFEST.items())))) == EXPECTED_DIGEST
    assert profile.manifest_digest({**profile.MANIFEST, "ltl-timeout": "61"}) != EXPECTED_DIGEST
