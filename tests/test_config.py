import pathlib
import tempfile

import akita_ddns.config as config_module


def reset_config_state():
    config_module._config = {}
    config_module._config_loaded = False
    config_module._loaded_config_path = None


def test_load_config_reloads_when_path_changes():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = pathlib.Path(tmpdir)
        config_a = tmp_path / "config_a.yaml"
        config_b = tmp_path / "config_b.yaml"

        config_a.write_text(
            "storage_path: './reticulum-a'\npersist_state: true\npersistence_path: './state-a'\n",
            encoding="utf-8",
        )
        config_b.write_text(
            "storage_path: './reticulum-b'\npersist_state: true\npersistence_path: './state-b'\n",
            encoding="utf-8",
        )

        reset_config_state()
        loaded_a = config_module.load_config(str(config_a))
        loaded_b = config_module.load_config(str(config_b))

        assert loaded_a["persistence_path"].endswith("state-a")
        assert loaded_b["persistence_path"].endswith("state-b")

        reset_config_state()