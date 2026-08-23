import sys

import RNS as ret

import akita_ddns.main as main_module


def test_top_level_help_does_not_start_application(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["akita-ddns", "--help"])

    status = main_module.main()

    assert status == 0
    assert "usage: akita-ddns" in capsys.readouterr().out


def test_configuration_failure_has_nonzero_status(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["akita-ddns", "server"])
    monkeypatch.setattr(
        main_module,
        "load_config",
        lambda path: (_ for _ in ()).throw(ValueError("bad")),
    )

    status = main_module.main()

    assert status == 2
    assert "Configuration error: bad" in capsys.readouterr().err


def test_cli_list_avoids_reticulum_startup(monkeypatch, tmp_path):
    identity = ret.Identity()
    config = {
        "storage_path": str(tmp_path),
        "akita_namespace_identity_hash": identity.hash.hex(),
    }
    seen = []
    monkeypatch.setattr(sys, "argv", ["akita-ddns", "cli", "list", "--registry"])
    monkeypatch.setattr(main_module, "load_config", lambda path: config)
    monkeypatch.setattr(main_module, "load_or_create_identity", lambda path: identity)
    monkeypatch.setattr(
        main_module, "run_cli", lambda args, cfg: seen.append(args.command) or 0
    )
    monkeypatch.setattr(
        main_module.ret,
        "Reticulum",
        lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("Reticulum should not start")
        ),
    )

    status = main_module.main()

    assert status == 0
    assert seen == ["list"]
