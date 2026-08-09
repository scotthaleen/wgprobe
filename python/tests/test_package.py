import inspect
import json
from importlib.metadata import distribution
from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import wgprobe

FAKE_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

if TYPE_CHECKING:
    wgprobe.probe_file("config", ping=["127.0.0.1"], resolve=("example.test",))
    wgprobe.probe_key_file(
        "key",
        FAKE_KEY,
        "127.0.0.1:1",
        allowed_ips=["0.0.0.0/0"],
        ping=("127.0.0.1",),
        resolve=["example.test"],
    )
    wgprobe.probe_file("config", ping="127.0.0.1")  # type: ignore[arg-type]
    wgprobe.probe_key_file(
        "key",
        FAKE_KEY,
        "127.0.0.1:1",
        allowed_ips="0.0.0.0/0",  # type: ignore[arg-type]
    )


def test_public_api_and_metadata() -> None:
    expected = [
        "ConfigurationError",
        "PhaseResult",
        "ProbeReport",
        "WgprobeError",
        "__version__",
        "probe_file",
        "probe_key_file",
    ]
    assert wgprobe.__all__ == expected
    assert wgprobe.__version__ == distribution_version("wgprobe")
    assert distribution("wgprobe").metadata["License-Expression"] == "MIT"
    assert issubclass(wgprobe.ConfigurationError, wgprobe.WgprobeError)
    assert str(inspect.signature(wgprobe.probe_file)) == (
        "(config_path, *, ping=(), resolve=(), dns_server=None, "
        "handshake_timeout_ms=3000, ping_timeout_ms=1000, dns_timeout_ms=2000, "
        "deadline_ms=9000)"
    )
    assert "allowed_ips=(), ping=(), resolve=()" in str(
        inspect.signature(wgprobe.probe_key_file)
    )
    wheel_files = {str(path) for path in distribution("wgprobe").files or ()}
    assert {
        "wgprobe/__init__.py",
        "wgprobe/__init__.pyi",
        "wgprobe/_wgprobe.pyi",
        "wgprobe/py.typed",
    } <= wheel_files
    assert any(path.endswith(".dist-info/licenses/LICENSE") for path in wheel_files)
    assert any(
        path.startswith("wgprobe/_wgprobe") and path.endswith((".so", ".pyd"))
        for path in wheel_files
    )


def test_configuration_errors_do_not_probe_network(tmp_path: Path) -> None:
    malformed = tmp_path / "malformed.txt"
    malformed.write_text("[Interface]\nPrivateKey = invalid\n")
    with pytest.raises(wgprobe.ConfigurationError):
        wgprobe.probe_file(malformed)

    key_file = tmp_path / "private-key.txt"
    key_file.write_text(FAKE_KEY)
    with pytest.raises(wgprobe.ConfigurationError, match="address"):
        wgprobe.probe_key_file(
            key_file,
            FAKE_KEY,
            "127.0.0.1:1",
            ping=("127.0.0.1",),
        )
    with pytest.raises(wgprobe.ConfigurationError, match="dns_server"):
        wgprobe.probe_key_file(
            key_file,
            FAKE_KEY,
            "127.0.0.1:1",
            address="10.0.0.2/32",
            allowed_ips=("0.0.0.0/0",),
            resolve=("example.test",),
        )
    with pytest.raises(wgprobe.ConfigurationError, match="1 through 86400000"):
        wgprobe.probe_key_file(key_file, FAKE_KEY, "127.0.0.1:1", deadline_ms=0)
    for huge_timeout in (86_400_001, 1 << 100, -(1 << 100)):
        with pytest.raises(wgprobe.ConfigurationError, match="1 through 86400000"):
            wgprobe.probe_key_file(
                key_file,
                FAKE_KEY,
                "127.0.0.1:1",
                handshake_timeout_ms=huge_timeout,
            )


def test_secret_paths_must_be_small_regular_files(tmp_path: Path) -> None:
    with pytest.raises(wgprobe.ConfigurationError, match="regular file"):
        wgprobe.probe_file(tmp_path)

    oversized_key = tmp_path / "oversized-key.txt"
    oversized_key.write_bytes(b"x" * 4097)
    with pytest.raises(wgprobe.ConfigurationError, match="4096-byte limit"):
        wgprobe.probe_key_file(oversized_key, FAKE_KEY, "127.0.0.1:1")


def test_local_endpoint_error_returns_frozen_typed_report(tmp_path: Path) -> None:
    config = tmp_path / "invalid-endpoint.txt"
    config.write_text(
        "[Interface]\n"
        f"PrivateKey = {FAKE_KEY}\n"
        "[Peer]\n"
        f"PublicKey = {FAKE_KEY}\n"
        "Endpoint = 127.0.0.1\n"
    )
    report = wgprobe.probe_file(config)
    assert isinstance(report, wgprobe.ProbeReport)
    assert report.verdict == "local_error"
    assert report.resolved_endpoint is None
    assert report.local_udp_address is None
    assert isinstance(report.phases, tuple)
    assert report.phases
    assert isinstance(report.phases[0], wgprobe.PhaseResult)
    assert report.phases[0].status == "error"
    assert json.loads(report.to_json())["verdict"] == "local_error"
    assert json.loads(report.phases[0].to_json())["status"] == "error"
    assert FAKE_KEY not in repr(report)
    assert FAKE_KEY not in repr(report.phases[0])
    with pytest.raises(AttributeError):
        report.verdict = "unconfirmed"  # type: ignore[misc]
