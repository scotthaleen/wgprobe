import gzip
from http.client import IncompleteRead
from pathlib import Path
from types import SimpleNamespace
from typing import NoReturn

import pytest

from examples import nord_find

FAKE_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def server(
    hostname: str,
    station: str,
    load: int,
    *,
    city: str = "Denver",
) -> dict[str, object]:
    return {
        "name": hostname,
        "hostname": hostname,
        "station": station,
        "load": load,
        "status": "online",
        "locations": [
            {"country": {"name": "United States", "city": {"name": city}}}
        ],
        "technologies": [
            {
                "identifier": "wireguard_udp",
                "metadata": [{"name": "public_key", "value": FAKE_KEY}],
                "pivot": {"status": "online"},
            }
        ],
    }


def test_resolves_exact_country_code_and_city() -> None:
    location = nord_find.resolve_location(
        [
            {
                "id": 228,
                "name": "United States",
                "code": "US",
                "cities": [{"id": 8770934, "name": "Denver"}],
            }
        ],
        "us",
        "denver",
    )

    assert location == nord_find.Location("United States", "Denver", 8770934)


def test_parses_deduplicates_and_diversifies_candidates() -> None:
    location = nord_find.Location("United States", "Denver", 8770934)
    first = server("us1.example", "8.8.8.1", 1)
    repeated_prefix = server("us2.example", "8.8.8.2", 2)
    distinct_prefix = server("us3.example", "1.1.1.1", 3)

    candidates = nord_find.parse_candidates(
        [
            repeated_prefix,
            first,
            distinct_prefix,
            first,
            server("wrong-city.example", "9.9.9.9", 0, city="Atlanta"),
            {"status": "online", "name": 7},
        ],
        location,
    )

    assert [candidate.hostname for candidate in candidates] == [
        "us1.example",
        "us3.example",
        "us2.example",
    ]


def test_rejects_control_text_and_invalid_wireguard_keys() -> None:
    assert nord_find.clean_text("safe.example") == "safe.example"
    assert nord_find.clean_text("unsafe\n.example") is None
    assert nord_find.wireguard_key(
        [
            {
                "identifier": "wireguard_udp",
                "metadata": [{"name": "public_key", "value": "not-base64"}],
                "pivot": {"status": "online"},
            }
        ]
    ) is None
    assert nord_find.wireguard_key(
        [
            {
                "identifier": "wireguard_udp",
                "metadata": [
                    {
                        "name": "public_key",
                        "value": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=",
                    }
                ],
                "pivot": {"status": "online"},
            }
        ]
    ) is None
    location = nord_find.Location("United States", "Denver", 8770934)
    assert nord_find.parse_candidate(server("local.example", "127.0.0.1", 1), location) is None


def test_key_path_and_incomplete_http_errors_are_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_value = "A" * 43 + "="
    with pytest.raises(nord_find.FinderError) as key_error:
        nord_find.validate_key_file(Path(key_value))
    assert key_value not in str(key_error.value)

    def incomplete(*_args: object, **_kwargs: object) -> NoReturn:
        raise IncompleteRead(b"partial", 100)

    monkeypatch.setattr(nord_find, "urlopen", incomplete)
    with pytest.raises(nord_find.FinderError, match="request failed"):
        nord_find.fetch_json(nord_find.COUNTRIES_URL)


def test_rejects_corrupt_or_oversized_decoded_gzip() -> None:
    with pytest.raises(nord_find.FinderError, match="invalid gzip"):
        nord_find.decode_body(b"\x1f\x8bcorrupt", "gzip")
    oversized = gzip.compress(b" " * (nord_find.MAX_JSON_BYTES + 1))
    with pytest.raises(nord_find.FinderError, match="decoded size limit"):
        nord_find.decode_body(oversized, "gzip")


def test_deeply_nested_json_is_an_inventory_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = b"[" * 10_000 + b"]" * 10_000

    def recursion_error(_document: object) -> NoReturn:
        raise RecursionError

    def run(*_args: object, **_kwargs: object) -> int:
        nord_find.decode_body(document, "identity")
        return 0

    monkeypatch.setattr("examples.nord_find.json.loads", recursion_error)
    monkeypatch.setattr(nord_find, "run", run)
    assert nord_find.main() == 2


def test_same_key_pacing_stops_after_confirmation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    candidates = [
        nord_find.Candidate("one", "one.example", "192.0.2.1:51820", FAKE_KEY, 1, "192.0.2"),
        nord_find.Candidate("two", "two.example", "192.0.3.1:51820", FAKE_KEY, 2, "192.0.3"),
        nord_find.Candidate("three", "three.example", "192.0.4.1:51820", FAKE_KEY, 3, "192.0.4"),
    ]
    reports = iter(
        [
            SimpleNamespace(verdict="unconfirmed", duration_ms=1),
            SimpleNamespace(verdict="authentication_confirmed", duration_ms=2),
        ]
    )
    starts = iter([0.0, 0.0, 2.0, 6.0])
    sleeps: list[float] = []
    monkeypatch.setattr(nord_find, "probe_key_file", lambda *_args, **_kwargs: next(reports))
    monkeypatch.setattr("examples.nord_find.time.monotonic", starts.__next__)
    monkeypatch.setattr("examples.nord_find.time.sleep", sleeps.append)

    result = nord_find.probe_candidates(tmp_path / "key", candidates, 3, False)

    assert result is not None
    assert result[0].hostname == "two.example"
    assert sleeps == [4.0]
    assert next(reports, None) is None
