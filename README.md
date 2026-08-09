# wgprobe

`wgprobe` is a provider-neutral userspace WireGuard probe. It answers one focused
question: can this identity authenticate with this endpoint? It verifies the
connection without creating a TUN interface, changing system routes, or
requiring administrator access.

## Three Ways to Use It

| Goal | Start here | What it provides |
| --- | --- | --- |
| Verify one WireGuard peer directly | [`wgprobe` CLI and Rust library](crates/wgprobe/README.md) | One short-lived handshake with optional IPv4 ping and DNS checks against a configuration or explicit endpoint |
| Add WireGuard verification to a script | [`wgprobe` Python package](python/README.md) | Typed synchronous Python bindings to the same provider-neutral probe engine |
| Find a working NordVPN endpoint | [`nordprobe`](crates/nordprobe/README.md) | A guided provider workflow built on `wgprobe`, with public inventory, safe pacing, confirmation, and export |

The `wgprobe` CLI and Rust library are the foundation. The Python package exposes
the same core for automation. `nordprobe` builds on it with the inventory and
workflow needed for NordVPN; the core itself never contacts a provider API or
handles provider account credentials.

`nordprobe` is an independent project and is not affiliated with or endorsed by
Nord Security.

## See It in Action

### Verify One Peer with wgprobe

![wgprobe running handshake, ping, and DNS checks and displaying a redacted evidence report](docs/wgprobe.gif)

`wgprobe` runs one explicit, provider-neutral probe and reports the evidence from
each phase.

### Find an Endpoint with Nordprobe

![Nordprobe terminal UI filtering locations, probing endpoints, and exporting a confirmed configuration](docs/tui.gif)

`nordprobe` is the guided NordVPN workflow built on the provider-neutral
`wgprobe` engine. See the [Nordprobe guide](crates/nordprobe/README.md) for the
terminal UI and command-line finder workflows.

## Safety and Evidence

Each `wgprobe` invocation tests one identity, server key, and endpoint through
one short-lived userspace WireGuard session. Each Nordprobe candidate attempt
uses the same model; a Nordprobe run schedules a bounded series of attempts.
Optional ping and DNS checks send inner IPv4 packets through the tested session.

An authenticated response confirms only that tested identity, server key, and
endpoint. `unconfirmed` is inconclusive. A passed ping or DNS check confirms only
that exchange; it does not establish a system VPN or prove general connectivity.

Secret-bearing buffers are zeroized where the implementation controls their
storage. Reports exclude private and preshared keys. Clipboard history, terminal
buffers after an explicit reveal, and exported configurations remain outside
that boundary and require separate protection.

## Quick Start

Build both native tools from the workspace root:

```sh
cargo build --release
```

**Warning:** A WireGuard configuration contains a private key and can contain a
preshared key. Restrict its permissions and keep it out of version control.

Probe one WireGuard endpoint:

```sh
target/release/wgprobe path/to/test.conf
```

For NordVPN inventory and endpoint selection, follow the Nordprobe
[private-key procedure](crates/nordprobe/README.md#get-the-nordlynx-private-key)
and launch:

```sh
target/release/nordprobe
```

## Development

Local verification does not contact Nord or public WireGuard endpoints:

```sh
cargo fmt --all --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace --release
cargo run -q -p wgprobe -- --help
cargo run -q -p nordprobe -- --help
```

The default workspace members are the native tools. `--workspace` also checks
the PyO3 crate; build and verify an installable extension with the
[Python guide](python/README.md#verify-the-packaged-wheel).

## License

This workspace is available under the [MIT License](LICENSE).
