#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///

"""Fetch the NordLynx private key associated with a Nord access token."""

from __future__ import annotations

import base64
import binascii
import contextlib
import getpass
import http.client
import json
import os
import sys
import warnings
from pathlib import Path

# Edit this path before running the example. Existing files are never overwritten.
OUTPUT_PATH = Path("path/to/private-key")

API_HOST = "api.nordvpn.com"
CREDENTIALS_PATH = "/v1/users/services/credentials"
MAX_RESPONSE_BYTES = 64 * 1024


class CredentialError(Exception):
    """A user-facing credential retrieval error that excludes secret values."""


def authorization(token: str) -> str:
    token = token.strip()
    if len(token) != 64 or not all(character in "0123456789abcdefABCDEF" for character in token):
        raise CredentialError("the access token must contain 64 hexadecimal characters")
    encoded = base64.b64encode(f"token:{token}".encode("ascii")).decode("ascii")
    return f"Basic {encoded}"


def parse_private_key(body: bytes) -> str:
    if len(body) > MAX_RESPONSE_BYTES:
        raise CredentialError("the credential response exceeded the size limit")
    try:
        document = json.loads(body)
        key = document["nordlynx_private_key"]
    except (KeyError, TypeError, RecursionError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CredentialError("Nord returned an invalid credential response") from error
    if not isinstance(key, str):
        raise CredentialError("Nord returned an invalid NordLynx private key")
    try:
        decoded = base64.b64decode(key, validate=True)
        if len(decoded) == 32 and base64.b64encode(decoded).decode("ascii") == key:
            return key
    except (binascii.Error, ValueError):
        pass
    try:
        decoded = bytes.fromhex(key)
    except ValueError as error:
        raise CredentialError("Nord returned an invalid NordLynx private key") from error
    if len(decoded) != 32:
        raise CredentialError("Nord returned an invalid NordLynx private key")
    return base64.b64encode(decoded).decode("ascii")


def fetch_private_key(token: str) -> str:
    connection = http.client.HTTPSConnection(API_HOST, timeout=30)
    try:
        connection.request(
            "GET",
            CREDENTIALS_PATH,
            headers={
                "Accept": "application/json",
                "Authorization": authorization(token),
            },
        )
        response = connection.getresponse()
        body = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, http.client.HTTPException) as error:
        raise CredentialError(f"Nord credential request failed: {error}") from error
    finally:
        connection.close()
    if response.status != 200:
        raise CredentialError(f"Nord credential request returned HTTP {response.status}")
    return parse_private_key(body)


def write_private_key(path: Path, key: str) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as error:
        raise CredentialError(f"could not create private-key file {path}: {error}") from error
    try:
        with os.fdopen(descriptor, "w", encoding="ascii") as file:
            file.write(f"{key}\n")
            file.flush()
            os.fsync(file.fileno())
    except BaseException as error:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        try:
            path.unlink()
        except OSError as cleanup_error:
            raise CredentialError(
                f"private-key write failed and sensitive partial file {path} could not be removed"
            ) from cleanup_error
        if isinstance(error, OSError):
            raise CredentialError(f"could not write private-key file {path}: {error}") from error
        raise


def read_access_token() -> str:
    if not sys.stdin.isatty():
        raise CredentialError("a terminal is required for hidden access-token input")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass("Nord access token: ")
    except getpass.GetPassWarning as error:
        raise CredentialError("hidden access-token input is unavailable") from error
    except EOFError as error:
        raise CredentialError("access-token input was cancelled") from error


def main() -> int:
    try:
        token = read_access_token()
        key = fetch_private_key(token)
        write_private_key(OUTPUT_PATH, key)
    except CredentialError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("cancelled", file=sys.stderr)
        return 130
    print(f"Wrote NordLynx private key to {OUTPUT_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
