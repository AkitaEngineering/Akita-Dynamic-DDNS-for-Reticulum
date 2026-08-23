import pathlib

import pytest

import akita_ddns.config as config_module


@pytest.fixture(autouse=True)
def reset_config_state():
    config_module._config = {}
    config_module._config_loaded = False
    config_module._loaded_config_path = None
    yield
    config_module._config = {}
    config_module._config_loaded = False
    config_module._loaded_config_path = None


def write_config(path: pathlib.Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def test_load_config_reloads_when_path_changes(tmp_path):
    config_a = tmp_path / "config_a.yaml"
    config_b = tmp_path / "config_b.yaml"
    write_config(config_a, "storage_path: './reticulum-a'\npersist_state: false\n")
    write_config(config_b, "storage_path: './reticulum-b'\npersist_state: false\n")

    loaded_a = config_module.load_config(str(config_a))
    loaded_b = config_module.load_config(str(config_b))

    assert loaded_a["storage_path"] == str(tmp_path / "reticulum-a")
    assert loaded_b["storage_path"] == str(tmp_path / "reticulum-b")


def test_string_false_is_not_coerced_to_true(tmp_path):
    path = tmp_path / "config.yaml"
    write_config(path, "persist_state: 'false'\nweb_ui_enabled: 'off'\n")

    loaded = config_module.load_config(str(path))

    assert loaded["persist_state"] is False
    assert loaded["web_ui_enabled"] is False


def test_unknown_option_fails_fast(tmp_path):
    path = tmp_path / "config.yaml"
    write_config(path, "gossip_intervl: 10\n")

    with pytest.raises(config_module.ConfigurationError, match="gossip_intervl"):
        config_module.load_config(str(path))


def test_duplicate_option_fails_fast(tmp_path):
    path = tmp_path / "config.yaml"
    write_config(path, "web_ui_enabled: true\nweb_ui_enabled: false\n")

    with pytest.raises(config_module.ConfigurationError, match="Duplicate"):
        config_module.load_config(str(path))


def test_mutating_web_api_requires_long_token(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    write_config(path, "web_ui_allow_mutations: true\n")
    monkeypatch.delenv("AKITA_WEB_UI_API_TOKEN", raising=False)

    with pytest.raises(config_module.ConfigurationError, match="web_ui_api_token"):
        config_module.load_config(str(path))


def test_web_token_can_come_from_environment(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    write_config(path, "web_ui_allow_mutations: true\n")
    monkeypatch.setenv("AKITA_WEB_UI_API_TOKEN", "s" * 32)

    loaded = config_module.load_config(str(path))

    assert loaded["web_ui_api_token"] == "s" * 32


def test_invalid_timing_relationship_is_rejected(tmp_path):
    path = tmp_path / "config.yaml"
    write_config(path, "gossip_interval: 120\npeer_ttl: 120\n")

    with pytest.raises(config_module.ConfigurationError, match="peer_ttl"):
        config_module.load_config(str(path))


def test_integer_settings_reject_lossy_float_values(tmp_path):
    path = tmp_path / "config.yaml"
    write_config(path, "default_ttl: 1.5\n")

    with pytest.raises(config_module.ConfigurationError, match="default_ttl"):
        config_module.load_config(str(path))


def test_numeric_settings_reject_non_finite_values(tmp_path):
    path = tmp_path / "config.yaml"
    write_config(path, "rate_limit_requests_per_sec: .nan\n")

    with pytest.raises(config_module.ConfigurationError, match="rate_limit"):
        config_module.load_config(str(path))


def test_persistence_filenames_must_be_distinct(tmp_path):
    path = tmp_path / "config.yaml"
    write_config(
        path,
        "registry_file: shared.yaml\nnamespace_owners_file: shared.yaml\n",
    )

    with pytest.raises(config_module.ConfigurationError, match="distinct"):
        config_module.load_config(str(path))


def test_persistence_filename_rejects_special_directory_names(tmp_path):
    path = tmp_path / "config.yaml"
    write_config(path, "registry_file: '..'\n")

    with pytest.raises(config_module.ConfigurationError, match="safe filename"):
        config_module.load_config(str(path))
