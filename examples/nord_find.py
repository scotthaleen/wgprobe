#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///

"""Find the first authenticated Nord WireGuard endpoint for an exact city."""

from __future__ import annotations

import base64
import binascii
import gzip
import ipaddress
import json
import stat
import sys
import time
import unicodedata
import zlib
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from http.client import HTTPException
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from wgprobe import ProbeReport, WgprobeError, probe_key_file

# Edit these values before running the example. Keep private-key contents out of source code.
PRIVATE_KEY_FILE = Path("path/to/private-key")
COUNTRY = "United States"
CITY = "Denver"
MAX_CANDIDATES = 12
FULL_CHECKS = False

API_BASE = "https://api.nordvpn.com/v1/servers"
COUNTRIES_URL = f"{API_BASE}/countries"
MAX_TRANSFER_BYTES = 4 * 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
SAME_KEY_INTERVAL_SECONDS = 6.0
CONFIRMED_VERDICTS = {"authentication_confirmed", "data_plane_confirmed"}

SERVER_QUERY = (
    ("limit", "10000"),
    ("filters[servers.status]", "online"),
    ("filters[servers_technologies][identifier]", "wireguard_udp"),
    ("filters[servers_technologies][pivot][status]", "online"),
    ("fields[servers.name]", ""),
    ("fields[servers.hostname]", ""),
    ("fields[servers.station]", ""),
    ("fields[servers.load]", ""),
    ("fields[servers.status]", ""),
    ("fields[servers.locations.country.name]", ""),
    ("fields[servers.locations.country.city.name]", ""),
    ("fields[servers.technologies.identifier]", ""),
    ("fields[servers.technologies.metadata]", ""),
    ("fields[servers.technologies.pivot.status]", ""),
)


class FinderError(Exception):
    """A safe, user-facing inventory or orchestration error."""


@dataclass(frozen=True)
class Location:
    country: str
    city: str
    city_id: int


@dataclass(frozen=True)
class Candidate:
    name: str
    hostname: str
    endpoint: str
    public_key: str
    load: int
    prefix: str


def fetch_json(url: str, parameters: Sequence[tuple[str, str]] = ()) -> object:
    query = urlencode(parameters)
    request_url = f"{url}?{query}" if query else url
    request = Request(
        request_url,
        headers={
            "Accept": "application/json",
            "Accept-Encoding": "gzip",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            encoded = response.read(MAX_TRANSFER_BYTES + 1)
            content_encoding = response.headers.get("Content-Encoding", "").lower().strip()
    except HTTPError as error:
        raise FinderError(f"Nord API returned HTTP {error.code}") from error
    except (HTTPException, TimeoutError, URLError, OSError) as error:
        raise FinderError(f"Nord API request failed: {error}") from error

    return decode_body(encoded, content_encoding)


def decode_body(encoded: bytes, content_encoding: str) -> object:
    if len(encoded) > MAX_TRANSFER_BYTES:
        raise FinderError("Nord API response exceeded the compressed size limit")
    if content_encoding == "gzip":
        try:
            with gzip.GzipFile(fileobj=BytesIO(encoded)) as stream:
                decoded = stream.read(MAX_JSON_BYTES + 1)
        except (EOFError, OSError, zlib.error) as error:
            raise FinderError("Nord API returned invalid gzip data") from error
    elif not content_encoding or content_encoding == "identity":
        decoded = encoded
    else:
        raise FinderError(f"Nord API returned unsupported content encoding {content_encoding!r}")
    if len(decoded) > MAX_JSON_BYTES:
        raise FinderError("Nord API response exceeded the decoded size limit")
    try:
        return json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise FinderError("Nord API returned invalid JSON") from error


def resolve_location(document: object, country_query: str, city_query: str) -> Location:
    if not isinstance(document, list):
        raise FinderError("Nord countries response is not a list")
    country_matches: list[dict[str, Any]] = []
    for value in document:
        if not isinstance(value, dict):
            continue
        name = clean_text(value.get("name"))
        code = clean_text(value.get("code"))
        if name is not None and (
            name.casefold() == country_query.casefold()
            or (code is not None and code.casefold() == country_query.casefold())
        ):
            country_matches.append(value)
    if len(country_matches) != 1:
        raise FinderError(f"country {country_query!r} did not match exactly one Nord country")

    country = country_matches[0]
    country_name = clean_text(country.get("name"))
    cities = country.get("cities")
    if not isinstance(country_name, str) or not isinstance(cities, list):
        raise FinderError("Nord country record is missing its name or cities")
    matches: list[Location] = []
    for value in cities:
        if not isinstance(value, dict):
            continue
        name = clean_text(value.get("name"))
        city_id = value.get("id")
        if (
            name is not None
            and name.casefold() == city_query.casefold()
            and isinstance(city_id, int)
            and not isinstance(city_id, bool)
            and city_id > 0
        ):
            matches.append(Location(country_name, name, city_id))
    if len(matches) != 1:
        raise FinderError(
            f"city {city_query!r} did not match exactly one city in {country_name!r}"
        )
    return matches[0]


def fetch_candidates(location: Location) -> list[Candidate]:
    parameters = (*SERVER_QUERY, ("filters[country_city_id]", str(location.city_id)))
    return parse_candidates(fetch_json(API_BASE, parameters), location)


def parse_candidates(document: object, location: Location) -> list[Candidate]:
    if not isinstance(document, list):
        raise FinderError("Nord server response is not a list")
    candidates: list[Candidate] = []
    seen: set[tuple[str, str]] = set()
    for record in document:
        candidate = parse_candidate(record, location)
        if candidate is None or (candidate.endpoint, candidate.public_key) in seen:
            continue
        seen.add((candidate.endpoint, candidate.public_key))
        candidates.append(candidate)
    if not candidates:
        raise FinderError(f"{location.city}, {location.country} has no usable WireGuard candidates")
    candidates.sort(key=lambda candidate: (candidate.load, candidate.name, candidate.hostname))
    return diversify_prefixes(candidates)


def parse_candidate(value: object, location: Location) -> Candidate | None:
    if not isinstance(value, dict) or value.get("status") != "online":
        return None
    name = clean_text(value.get("name"))
    hostname = clean_text(value.get("hostname"))
    station = value.get("station")
    load = value.get("load")
    if (
        name is None
        or hostname is None
        or not isinstance(station, str)
        or not isinstance(load, int)
        or isinstance(load, bool)
        or not 0 <= load <= 100
        or not location_matches(value.get("locations"), location)
    ):
        return None
    try:
        address = ipaddress.ip_address(station)
    except ValueError:
        return None
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
        return None
    public_key = wireguard_key(value.get("technologies"))
    if public_key is None:
        return None
    endpoint = f"{address}:51820"
    prefix = ".".join(str(part) for part in address.packed[:3])
    return Candidate(name, hostname, endpoint, public_key, load, prefix)


def clean_text(value: object) -> str | None:
    if (
        not isinstance(value, str)
        or not value
        or any(unicodedata.category(character).startswith("C") for character in value)
    ):
        return None
    return value


def location_matches(value: object, location: Location) -> bool:
    if not isinstance(value, list):
        return False
    for item in value:
        if not isinstance(item, dict):
            continue
        country = item.get("country")
        if not isinstance(country, dict):
            continue
        city = country.get("city")
        if (
            isinstance(city, dict)
            and country.get("name") == location.country
            and city.get("name") == location.city
        ):
            return True
    return False


def wireguard_key(value: object) -> str | None:
    if not isinstance(value, list):
        return None
    for technology in value:
        if (
            not isinstance(technology, dict)
            or technology.get("identifier") != "wireguard_udp"
        ):
            continue
        pivot = technology.get("pivot")
        metadata = technology.get("metadata")
        if not isinstance(pivot, dict) or pivot.get("status") != "online":
            continue
        if not isinstance(metadata, list):
            continue
        for item in metadata:
            if not isinstance(item, dict) or item.get("name") != "public_key":
                continue
            key = item.get("value")
            if not isinstance(key, str):
                continue
            try:
                decoded = base64.b64decode(key, validate=True)
            except (binascii.Error, ValueError):
                continue
            if len(decoded) == 32 and base64.b64encode(decoded).decode("ascii") == key:
                return key
    return None


def diversify_prefixes(candidates: Sequence[Candidate]) -> list[Candidate]:
    seen: set[str] = set()
    distinct: list[Candidate] = []
    repeated: list[Candidate] = []
    for candidate in candidates:
        if candidate.prefix in seen:
            repeated.append(candidate)
        else:
            seen.add(candidate.prefix)
            distinct.append(candidate)
    return distinct + repeated


def validate_key_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise FinderError("could not inspect the private-key file path") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise FinderError("the private-key path must name a regular file, not a symbolic link")
    if metadata.st_size > 4096:
        raise FinderError("the private-key file exceeds the 4096-byte limit")


def probe_candidates(
    key_file: Path,
    candidates: Sequence[Candidate],
    maximum: int,
    full: bool,
) -> tuple[Candidate, ProbeReport] | None:
    last_started: dict[str, float] = {}
    for index, candidate in enumerate(candidates[:maximum], start=1):
        elapsed = time.monotonic() - last_started.get(candidate.public_key, float("-inf"))
        if elapsed < SAME_KEY_INTERVAL_SECONDS:
            time.sleep(SAME_KEY_INTERVAL_SECONDS - elapsed)
        print(
            f"[{index}/{min(maximum, len(candidates))}] probing "
            f"{candidate.hostname} ({candidate.endpoint}, load {candidate.load}%)",
            file=sys.stderr,
        )
        last_started[candidate.public_key] = time.monotonic()
        try:
            if full:
                report = probe_key_file(
                    key_file,
                    candidate.public_key,
                    candidate.endpoint,
                    address="10.5.0.2/32",
                    allowed_ips=("0.0.0.0/0",),
                    ping=("1.1.1.1",),
                    resolve=("example.com",),
                    dns_server="103.86.96.100",
                )
            else:
                report = probe_key_file(
                    key_file,
                    candidate.public_key,
                    candidate.endpoint,
                )
        except WgprobeError as error:
            raise FinderError(
                "probe configuration failed; verify the private-key file and candidate inputs"
            ) from error
        print(f"  {report.verdict} ({report.duration_ms} ms)", file=sys.stderr)
        if report.verdict in CONFIRMED_VERDICTS:
            return candidate, report
    return None


def run(
    key_file: Path,
    country: str,
    city: str,
    max_candidates: int = 12,
    full_checks: bool = False,
) -> int:
    if not 1 <= max_candidates <= 100:
        raise FinderError("max_candidates must be from 1 through 100")
    validate_key_file(key_file)
    location = resolve_location(fetch_json(COUNTRIES_URL), country, city)
    candidates = fetch_candidates(location)
    print(
        f"Location: {location.city}, {location.country} ({len(candidates)} candidates)",
        file=sys.stderr,
    )
    result = probe_candidates(
        key_file,
        candidates,
        max_candidates,
        full_checks,
    )
    if result is None:
        print("No candidate returned an authenticated response", file=sys.stderr)
        return 1
    candidate, report = result
    candidate_document = asdict(candidate)
    candidate_document.pop("prefix")
    output = {
        "location": {"country": location.country, "city": location.city},
        "candidate": candidate_document,
        "report": json.loads(report.to_json()),
    }
    print(json.dumps(output, separators=(",", ":"), sort_keys=True))
    return 0


def main() -> int:
    try:
        return run(PRIVATE_KEY_FILE, COUNTRY, CITY, MAX_CANDIDATES, FULL_CHECKS)
    except FinderError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("cancelled", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
