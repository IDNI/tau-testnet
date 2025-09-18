import config
from app.container import ServiceContainer


def test_container_uses_settings_env():
    container = ServiceContainer.build()
    assert container.settings is config.settings
    network_cfg = container.build_network_config()
    assert network_cfg.network_id == config.settings.network.network_id
    assert network_cfg.genesis_hash == config.settings.network.genesis_hash


class DummyLogger:
    pass


def test_container_overrides_logger():
    fake_logger = DummyLogger()
    container = ServiceContainer.build(overrides={"logger": fake_logger})
    assert container.logger is fake_logger
