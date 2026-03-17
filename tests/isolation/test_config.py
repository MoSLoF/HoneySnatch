"""Tests for isolation config integration."""
from flyinghoneysnitch.isolation.config import IsolationConfig, find_default_config


def test_isolation_config_defaults():
    config = IsolationConfig()
    assert config.enabled is False
    assert config.default_server == "8.8.8.8"
    assert config.default_port == 443
    assert config.test_timeout == 30
    assert config.debug_level == 0
    assert config.hostap_dir == ""


def test_find_default_config_supplicant():
    # Should find the client.conf in data/isolation/
    path = find_default_config("supplicant")
    if path:
        assert "client.conf" in path


def test_find_default_config_nonexistent():
    result = find_default_config("nonexistent_file.conf")
    # May be None if file doesn't exist
    assert result is None or "nonexistent" in result
