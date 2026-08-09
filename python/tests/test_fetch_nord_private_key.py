import base64
import os
from pathlib import Path

import pytest

from examples import fetch_nord_private_key

FAKE_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def test_validates_access_tokens_and_private_keys() -> None:
    header = fetch_nord_private_key.authorization("a" * 64)
    assert header.startswith("Basic ")
    assert "a" * 64 not in header
    assert (
        fetch_nord_private_key.parse_private_key(
            b'{"nordlynx_private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}'
        )
        == FAKE_KEY
    )
    assert (
        fetch_nord_private_key.parse_private_key(
            b'{"nordlynx_private_key":"0000000000000000000000000000000000000000000000000000000000000000"}'
        )
        == FAKE_KEY
    )

    with pytest.raises(fetch_nord_private_key.CredentialError, match="64 hexadecimal"):
        fetch_nord_private_key.authorization("not-a-token")
    with pytest.raises(fetch_nord_private_key.CredentialError, match="invalid NordLynx"):
        fetch_nord_private_key.parse_private_key(b'{"nordlynx_private_key":"bad"}')
    with pytest.raises(fetch_nord_private_key.CredentialError, match="invalid credential"):
        fetch_nord_private_key.parse_private_key(b"null")


def test_writes_restrictive_file_without_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "private-key"
    fetch_nord_private_key.write_private_key(path, FAKE_KEY)

    assert path.read_text() == f"{FAKE_KEY}\n"
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(fetch_nord_private_key.CredentialError, match="could not create"):
        fetch_nord_private_key.write_private_key(path, FAKE_KEY)


def test_fetches_credentials_over_fixed_https_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    class Response:
        status = 200

        def read(self, maximum: int) -> bytes:
            assert maximum == fetch_nord_private_key.MAX_RESPONSE_BYTES + 1
            return b'{"nordlynx_private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}'

    class Connection:
        def __init__(self) -> None:
            self.request_args: tuple[str, str, dict[str, str]] | None = None
            self.closed = False

        def request(self, method: str, path: str, *, headers: dict[str, str]) -> None:
            self.request_args = (method, path, headers)

        def getresponse(self) -> Response:
            return Response()

        def close(self) -> None:
            self.closed = True

    connection = Connection()

    def connect(host: str, *, timeout: int) -> Connection:
        assert host == fetch_nord_private_key.API_HOST
        assert timeout == 30
        return connection

    monkeypatch.setattr("examples.fetch_nord_private_key.http.client.HTTPSConnection", connect)
    assert fetch_nord_private_key.fetch_private_key("a" * 64) == FAKE_KEY
    assert connection.request_args is not None
    method, path, headers = connection.request_args
    assert (method, path) == ("GET", fetch_nord_private_key.CREDENTIALS_PATH)
    assert headers["Authorization"].startswith("Basic ")
    assert "a" * 64 not in headers["Authorization"]
    encoded = headers["Authorization"].removeprefix("Basic ")
    assert base64.b64decode(encoded).decode("ascii") == f"token:{'a' * 64}"
    assert connection.closed


def test_hidden_prompt_handles_end_of_input(monkeypatch: pytest.MonkeyPatch) -> None:
    class TerminalInput:
        def isatty(self) -> bool:
            return True

    def end_of_input(_prompt: str) -> str:
        raise EOFError

    monkeypatch.setattr("examples.fetch_nord_private_key.sys.stdin", TerminalInput())
    monkeypatch.setattr("examples.fetch_nord_private_key.getpass.getpass", end_of_input)
    with pytest.raises(fetch_nord_private_key.CredentialError, match="cancelled"):
        fetch_nord_private_key.read_access_token()
