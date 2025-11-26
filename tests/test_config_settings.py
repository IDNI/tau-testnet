import os

import config


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
    assert config.MINER_PUBKEY.endswith("d2eebce6")
    assert config.STATE_LOCATOR_NAMESPACE == "state"
    assert config.BLOCK_SIGNATURE_SCHEME == "bls_g2"
