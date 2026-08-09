# wgprobe

`wgprobe` tests one WireGuard peer through one short-lived userspace session.
Every run attempts an authenticated handshake; optional IPv4 ping and DNS checks
use the same UDP socket and BoringTun session.

It does not create a TUN interface, install routes, require administrator access,
or provide inventory, retries, batching, and orchestration.

## Quick Start

Requirements are a Rust toolchain, outbound UDP access, and either a one-peer
configuration or explicit key-file, peer-key, and endpoint inputs.

Build with `cargo build -p wgprobe --release`. The executable is
`target/release/wgprobe`.

**Warning:** Configuration and private-key files contain secrets. Restrict their
permissions, keep them out of version control, and never put key values in shell
arguments or logs.

Create one configuration outside the repository. `Address`, `DNS`, and
`AllowedIPs` are required only for the corresponding data checks:

```ini
[Interface]
PrivateKey = <client-private-key>
Address = 10.5.0.2/32
DNS = 10.5.0.1

[Peer]
PublicKey = <server-public-key>
PresharedKey = <optional-preshared-key>
AllowedIPs = 0.0.0.0/0
Endpoint = <server-host-or-ip>:51820
```

Run a handshake-only probe:

```sh
target/release/wgprobe path/to/test.conf
```

Use `-` to read a configuration from standard input. Named configuration and
private-key paths must be regular files; symbolic links and other file types are
rejected.

## Rust Library

The crate exposes `ProbeConfig`, `ProbePlan`, `probe`, progress events, and
serializable reports. Configuration and plan validation return errors before
network work; operational failures after probing starts are represented in the
report.

## Input Modes

| Mode | Required identity input | Data-check additions | DNS addition |
| --- | --- | --- | --- |
| Configuration | One-peer configuration | IPv4 `Interface.Address` and matching peer `AllowedIPs` | First `Interface.DNS` entry, which must be IPv4, or `--dns-server` |
| Raw key | `--private-key-file`, `--peer-key`, `--endpoint` | `--address` and one or more `--allowed-ip` | `--dns-server` |

Run `wgprobe --help` for complete raw-key syntax.

## Ping and DNS Checks

```sh
target/release/wgprobe path/to/test.conf \
  --ping 1.1.1.1 \
  --resolve example.com
```

`--ping` and `--resolve` are repeatable. Every ping target and DNS server must be
inside the peer's IPv4 `AllowedIPs`. Checks run sequentially and independently;
data checks are skipped when authentication is not confirmed.

| Operation | Positive evidence | Limitation |
| --- | --- | --- |
| Handshake | The tested identity authenticated the tested server key at the resolved endpoint. | Silence is inconclusive. |
| Keepalive | The initial encrypted keepalive was sent. | WireGuard does not acknowledge it, so its status is `sent`. |
| Ping | A matching ICMP reply crossed the authenticated session. | Does not prove other destinations or protocols. |
| DNS | A valid matching response came from the selected server; zero A records still passes. | Does not prove general DNS or Internet access. |

## Output and Verdicts

| Mode | Standard error | Standard output |
| --- | --- | --- |
| Default | Phase progress, colored on a terminal | Human report, colored on a terminal |
| `--quiet` | Suppressed | Human report, colored on a terminal |
| `--json` | Suppressed | One compact JSON report with no ANSI output |

Color defaults to interactive terminals only and honors `NO_COLOR`. Use
`--color always` for captured terminal output or `--color never` for stable plain
text. Human phase results use colored status badges, or bracketed labels without
color. JSON output never contains ANSI escapes.

Use `--redact` before sharing a report or terminal recording. It replaces the
derived client public key and local UDP address with solid bars in human output.
JSON uses redaction markers for text fields and `null` for the local address. It
does not hide the public server endpoint, check targets, DNS answers, timings, or
byte counts.

Phase statuses are:

| Status | Meaning |
| --- | --- |
| `passed` | A valid matching response arrived. |
| `sent` | A packet was sent without an expected acknowledgement. |
| `unconfirmed` | No valid response arrived before the phase deadline. |
| `skipped` | Authentication was not confirmed, so the check did not run. |
| `error` | Local validation, socket, packet, or protocol processing failed. |

| Verdict | Meaning | Exit status |
| --- | --- | --- |
| `authentication_confirmed` | Authentication succeeded without a passed data check. | 0 |
| `data_plane_confirmed` | Authentication and at least one data check succeeded. | 0 |
| `unconfirmed` | No authenticated response was confirmed. | Nonzero |
| `local_error` | A local operation failed. | Nonzero |

Data-check failures do not change a confirmed authentication verdict to failure.
Configuration and command-line errors exit nonzero.

JSON schema version 1 includes configured and resolved endpoints, local UDP
address, derived client public key, durations, byte counts, and phase details.
It excludes private and preshared keys.

## Limits and Resolution

| Limit | Value |
| --- | --- |
| Handshake timeout | `--timeout-ms`, default 3000 ms |
| Ping timeout | `--ping-timeout-ms`, default 1000 ms per target |
| DNS timeout | `--dns-timeout-ms`, default 2000 ms per query |
| Whole run | `--deadline-ms`, default 9000 ms |
| Named configuration input | Regular file, at most 1 MiB |
| Configuration stdin | At most 1 MiB |
| Private-key file | Regular file, at most 4096 bytes |
| Resolver capacity | Four outstanding operating-system resolver calls |

Timeouts must be positive and representable by the system clock. The overall
deadline caps each phase. There are no retries.

Numeric endpoints bypass resolution. Hostname resolution is not cancellable and
can outlive the probe deadline in a bounded background worker. The first
resolved address is the only address attempted.

## Security

Secret-bearing input uses zeroizing buffers. Reports contain the derived public
key unless `--redact` is set, but never contain the private or preshared key.
Treat endpoints, reports, and error details as sensitive operational metadata.

WireGuard protocol processing uses Cloudflare's BSD-licensed `boringtun` crate.
