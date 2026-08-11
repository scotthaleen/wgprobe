# wgprobe Python package

The optional `wgprobe` package provides typed synchronous bindings to the
generic Rust probe. It has no provider API or account coupling and uses Python's
stable ABI for Python 3.10 and newer.

**Warning:** Configuration and private-key files contain secrets. Restrict their
permissions, keep them out of version control, and never put key values in
source, logs, command-line arguments, or environment variables.

## Install

Install a Python 3.10+ wheel from PyPI:

```sh
python -m pip install wgprobe
```

## Build from Source

Requirements are Python 3.10 or newer, a Rust toolchain, and a PEP 517 wheel
builder. Build from the workspace root without installing Maturin globally:

```sh
uv run --isolated --with 'maturin>=1.14,<2' \
  maturin build --release --out dist
```

Install the exact platform-specific wheel emitted under `dist/`:

```sh
WHEEL='dist/wgprobe-0.1.0-<python-abi-platform>.whl'
python -m pip install "$WHEEL"
```

## Usage

Probe a one-peer configuration:

```python
from wgprobe import probe_file

report = probe_file(
    "path/to/test.conf",
    ping=("10.5.0.1",),
    resolve=("example.com",),
)
print(report.verdict)
for phase in report.phases:
    print(phase.phase, phase.status, phase.detail)
```

The configuration must contain one peer. Data checks require IPv4
`Interface.Address`, matching peer `AllowedIPs`, and an IPv4 DNS server for DNS
queries.

Probe explicit key and endpoint inputs:

```python
from wgprobe import probe_key_file

report = probe_key_file(
    "path/to/private-key",
    "<server-public-key>",
    "<server-host-or-ip>:51820",
    address="10.5.0.2/32",
    allowed_ips=("0.0.0.0/0",),
    ping=("1.1.1.1",),
    resolve=("example.com",),
    dns_server="103.86.96.100",
)
print(report.verdict, report.resolved_endpoint)
```

Omit all data-check arguments for a handshake-only call. Raw-key data checks
require `address` and at least one `allowed_ips` entry; DNS also requires
`dns_server`.

For a provider-specific integration, see the editable
[`examples/nord_find.py`](../examples/nord_find.py) script:

```sh
uv run --with . examples/nord_find.py
```

It probes sequentially, tries each candidate once, and enforces six seconds
between starts that share a server key. Progress goes to standard error; a
confirmed result is compact JSON on standard output. Exit statuses are 0 for a
confirmation, 1 for none, and 2 for inventory or configuration errors. The
script has no cache or export; use native `nordprobe find` for those features.

## API Contracts

The checked [`_wgprobe.pyi`](wgprobe/_wgprobe.pyi) stub is the canonical function
signature reference.

| Contract | Detail |
| --- | --- |
| Paths | `str` or `os.PathLike[str]` |
| Collections | Lists or tuples of strings; bare strings are rejected |
| Network values | Ping and DNS servers are IPv4; addresses and routes are IPv4 CIDRs |
| `ProbeReport` | Frozen `schema_version`, verdict, configured/resolved endpoint, local UDP address, client public key, duration, byte counts, and immutable `phases` tuple |
| `PhaseResult` | Frozen phase, target, status, duration, byte counts, and detail |
| Serialization | Both report classes provide `to_json()` |
| Exceptions | `WgprobeError` is the package base exception; `ConfigurationError` covers invalid local inputs and plans |
| Version | `wgprobe.__version__` reports the package version |

## Verdicts and Errors

Reports use the stable verdict and phase-status names defined in the
[`wgprobe` evidence contract](../crates/wgprobe/README.md#output-and-verdicts). A
passed ping or DNS phase confirms only that exchange, not general connectivity.

Invalid files, keys, addresses, routes, DNS arguments, timeouts, and plans raise
`ConfigurationError` before probing. Operational `unconfirmed` and `local_error`
outcomes return reports for inspection.

## Synchronous and Async Use

Calls are synchronous. Rust releases the global interpreter lock while reading
and parsing secret files and while probing. Offload calls from an asyncio event
loop:

```python
import asyncio
from wgprobe import probe_file

report = await asyncio.to_thread(probe_file, "path/to/test.conf")
```

Cancelling the awaiting task does not cancel the Rust probe or an operating-
system resolver call.

## Limits and Security

| Limit | Value |
| --- | --- |
| Configuration file | Regular file, at most 1,048,576 bytes |
| Private-key file | Regular file, at most 4096 bytes |
| Secret paths | Symbolic links, directories, devices, and FIFOs are rejected |
| Timeout arguments | Integers from 1 through 86,400,000 milliseconds |
| Resolver capacity | Four outstanding operating-system resolver calls |
| Data checks | Inner IPv4 only, sequential, no retries |

The overall deadline caps phase timeouts. Shared probe and resolver behavior is
documented in the [core limits](../crates/wgprobe/README.md#limits-and-resolution).

Secret files are read into zeroizing Rust buffers. Reports and representations
contain the derived client public key but no private or preshared key. Treat
reports as sensitive operational metadata.

## Verify the Packaged Wheel

Cargo tests do not validate an installed extension. Set the exact wheel path
emitted by Maturin, then run:

```sh
WHEEL='./dist/wgprobe-0.1.0-cp310-abi3-<platform>.whl'

uv run --isolated --with "$WHEEL" --with 'pytest>=9,<10' \
  pytest python/tests
uv run --isolated --with "$WHEEL" --with 'mypy>=1.19,<2' mypy
uv run --isolated --with "$WHEEL" --with 'ruff>=0.14,<1' ruff check .
```

Run Rust tests separately:

```sh
cargo test --workspace
```
