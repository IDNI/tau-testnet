import os

import pytest

import config
from errors import ConfigurationError


def test_test_environment_loaded_by_default():
    assert config.settings.env == "test"
    assert config.CLIENT_WAIT_TIMEOUT == config.settings.timeouts.client_wait_timeout == 5
    assert config.LOGGING.level.upper() == "DEBUG"


def test_reload_settings_switch_environment(monkeypatch):
    monkeypatch.setenv("TAU_ENV", "production")
    new_settings = config.reload_settings(env="production")
    assert new_settings.env == "production"
    assert config.LOGGING.level.upper() == "WARNING"

    # restore test environment for subsequent tests
    monkeypatch.setenv("TAU_ENV", "test")
    config.reload_settings(env="test")


def test_set_database_path(temp_database):
    expected = temp_database
    assert config.STRING_DB_PATH == expected


def test_authority_settings_defaults():
    assert config.MINER_PUBKEY.endswith("d5c45")
    assert config.MINER_PUBKEYS == []
    assert config.STATE_LOCATOR_NAMESPACE == "state"
    assert config.BLOCK_SIGNATURE_SCHEME == "bls_g2"


def test_miner_pubkeys_env_exports_validator_set(monkeypatch):
    validator_one = "a" * 96
    validator_two = "b" * 96
    monkeypatch.setenv("TAU_MINER_PUBKEYS", f"{validator_one}, {validator_two}")

    try:
        new_settings = config.reload_settings(env="test")
        assert new_settings.authority.miner_pubkeys == [validator_one, validator_two]
        assert config.MINER_PUBKEYS == [validator_one, validator_two]
    finally:
        monkeypatch.delenv("TAU_MINER_PUBKEYS", raising=False)
        config.reload_settings(env="test")


def test_miner_pubkeys_env_rejects_invalid_pubkey(monkeypatch):
    monkeypatch.setenv("TAU_MINER_PUBKEYS", "A" * 96)

    try:
        with pytest.raises(ConfigurationError, match="miner_pubkeys\\[0\\]"):
            config.reload_settings(env="test")
    finally:
        monkeypatch.delenv("TAU_MINER_PUBKEYS", raising=False)
        config.reload_settings(env="test")
