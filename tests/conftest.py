"""Shared pytest fixtures for the Tau Testnet test-suite."""
from __future__ import annotations

import os
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
import db
import tau_logging


@pytest.fixture(scope="session", autouse=True)
def test_environment() -> Iterator[None]:
    """Ensure tests run with the dedicated 'test' configuration and logging."""
    original_env = os.environ.get("TAU_ENV")
    os.environ["TAU_ENV"] = "test"
    os.environ.setdefault("TAU_FORCE_TEST", "1")

    config.reload_settings(env="test")
    tau_logging.configure(config.LOGGING, force=True)

    yield

    if original_env is None:
        os.environ.pop("TAU_ENV", None)
        config.reload_settings(env="development")
    else:
        os.environ["TAU_ENV"] = original_env
        config.reload_settings(env=original_env)


@pytest.fixture()
def temp_database(tmp_path) -> Iterator[str]:
    """Provide a temporary SQLite database path and ensure cleanup."""
    original_path = config.STRING_DB_PATH
    db_path = tmp_path / "node.sqlite"
    config.set_database_path(str(db_path))

    if getattr(db, "_db_conn", None) is not None:
        db._db_conn.close()
        db._db_conn = None

    db.init_db()
    yield str(db_path)

    if getattr(db, "_db_conn", None) is not None:
        db._db_conn.close()
        db._db_conn = None
    config.set_database_path(original_path)

def pytest_sessionfinish(session, exitstatus):
    """
    Bypass standard Python exit to avoid native segfaults caused by 
    upstream tau-lang destructors when tearing down global test state.
    """
    os._exit(exitstatus)
