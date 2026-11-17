"""The autouse check of tests/conftest.py fails a test that leaks a patch."""
import os
import re
import shutil
import subprocess
import sys
from unittest.mock import patch

import pytest

from conftest import _fail_on_new_patches, active_patches


def _leaky_helper():
    patch("os.getcwd", return_value="/leaked").start()
    patch.dict("os.environ", {"PATCH_LEAK_CHECK": "1"}).start()


def test_a_leaked_patch_fails_the_test_and_is_stopped():
    before = set(active_patches())
    _leaky_helper()
    with pytest.raises(pytest.fail.Exception,
                       match=r"the leaky helper left mock patches active: \['os.environ', 'os.getcwd'\]"):
        _fail_on_new_patches(before, "the leaky helper")
    assert os.getcwd() != "/leaked"
    assert "PATCH_LEAK_CHECK" not in os.environ
    assert set(active_patches()) == before


def test_two_leaked_patches_of_one_attribute_give_back_the_original():
    original = os.getcwd
    before = set(active_patches())
    patch("os.getcwd", return_value="/first").start()
    patch("os.getcwd", return_value="/second").start()
    with pytest.raises(pytest.fail.Exception, match="left mock patches active"):
        _fail_on_new_patches(before, "the leaky helper")
    assert os.getcwd is original


def test_a_stopped_patch_passes_the_check():
    before = set(active_patches())
    started = patch("os.getcwd", return_value="/stopped")
    started.start()
    started.stop()
    _fail_on_new_patches(before, "a clean helper")


def test_a_leaked_patch_multiple_names_each_attribute():
    before = set(active_patches())
    patch.multiple("os", getcwd=lambda: "/leaked", getpid=lambda: 0).start()
    with pytest.raises(pytest.fail.Exception,
                       match=r"left mock patches active: \['os.getcwd', 'os.getpid'\]"):
        _fail_on_new_patches(before, "the leaky helper")
    assert os.getcwd() != "/leaked"
    assert os.getpid() != 0


_CLASS_LEAK_TESTS = '''
import os
import unittest
from unittest.mock import patch


class TestLeakyClass(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        patch("os.getcwd", return_value="/leaked").start()

    def test_one(self):
        pass


class TestCleanClass(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.started = patch("os.getpid", return_value=0)
        cls.started.start()

    @classmethod
    def tearDownClass(cls):
        cls.started.stop()

    def test_one(self):
        pass


def test_after_the_classes():
    assert os.getcwd() != "/leaked"
    assert os.getpid() != 0
'''


def test_a_leak_in_setupclass_fails_at_the_end_of_the_class(tmp_path):
    tests_dir = os.path.dirname(os.path.abspath(__file__))
    shutil.copy(os.path.join(tests_dir, "conftest.py"), tmp_path / "conftest.py")
    (tmp_path / "test_class_leak.py").write_text(_CLASS_LEAK_TESTS)
    # An ini file here keeps the rootdir, and so the node ids, in tmp_path.
    (tmp_path / "pytest.ini").write_text("[pytest]\n")
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (os.path.dirname(tests_dir), env.get("PYTHONPATH")) if p)
    env["COLUMNS"] = "1000"
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-rfE", "--tb=no", "-p", "no:cacheprovider",
         str(tmp_path)],
        cwd=tmp_path, capture_output=True, text=True, env=env, timeout=300)
    out = proc.stdout + proc.stderr
    assert "test_class_leak.py::TestLeakyClass left mock patches active: ['os.getcwd']" in out, out
    assert out.count("left mock patches active") == 1, out
    # A warning count can stand between the counts, so check each count alone.
    summary = next(line for line in reversed(proc.stdout.splitlines())
                   if re.search(r" in [0-9.]+s", line))
    assert re.search(r"\b3 passed\b", summary), out
    assert re.search(r"\b1 error\b", summary), out
