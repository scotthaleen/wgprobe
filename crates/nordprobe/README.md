# nordprobe

`nordprobe` browses public Nord inventory, runs bounded WireGuard probes, and
exports configurations for authenticated endpoints. It uses the generic
`wgprobe` library without creating a TUN interface, changing routes, or starting
another process.

Nordprobe is independent and is not affiliated with or endorsed by Nord
Security.

## Requirements and Key Safety

- A Rust toolchain.
- An interactive terminal for the TUI and when `find` must resolve an ambiguous
  location selection.
- HTTPS access to Nord's public inventory API.
- Outbound UDP access to candidate endpoints on port 51820.
- One base64 WireGuard private key. The TUI accepts a file or one paste; `find`
  requires a file.

**Warning:** Restrict access to private-key files and exports, and keep them out
of version control. Never put key contents in command-line arguments or
environment variables.

Nordprobe accepts exactly one trimmed base64 key. It rejects embedded whitespace,
extra content, and WireGuard configuration files. The TUI does not retrieve
credentials or select a key file automatically; `key fetch` performs the
explicit access-token exchange described below.

The TUI masks pasted input and can reveal it with `F2` before validation. It then
zeroizes the editable paste buffer and pins the validated identity to every
attempt and export in that run. Clipboard history and terminal buffers remain
outside Nordprobe's control.

### Get the NordLynx Private Key

1. Sign in to the [Nord Account dashboard](https://my.nordaccount.com/dashboard/nordvpn/).
2. Open **NordVPN**, then under **Advanced settings** select **Get access token**.
3. Verify your email and generate a token. Nord shows it once; treat it as a
   secret. A temporary token is sufficient for this procedure.
4. On Unix, run the native key command and enter the token at the hidden prompt:

```sh
cargo run -p nordprobe --release -- \
  key fetch --output path/to/private-key
```

The native command requires Unix so it can create the file atomically with mode
`0600`. It uses Nord's service-credentials endpoint, normalizes the returned
`nordlynx_private_key` to WireGuard base64, and never overwrites an existing path
or prints the token or key. Revoke the access token in Nord Account when it is no
longer needed.

On other platforms, obtain the key on a trusted Unix system and transfer it
using platform-appropriate access controls.

Nord documents [access-token generation](https://support.nordvpn.com/hc/en-us/articles/20286980309265-How-to-log-in-to-NordVPN-without-a-GUI-using-a-token),
and its [official open-source client](https://github.com/NordSecurity/libtelio/blob/main/clis/nordvpnlite/src/core_api.rs)
uses the same credentials endpoint.

## Commands

Build and launch from the workspace root:

```sh
cargo run -p nordprobe --release
```

The TUI displays its controls on each screen. `--key-file` bypasses Setup;
`--key-file` and `--export-directory` are available only with the TUI and `find`.

### Assisted Find

`find` selects one location, stops after the first authenticated endpoint, and
exports its configuration:

```sh
cargo run -p nordprobe --release -- \
  --key-file path/to/private-key \
  find --country "United States" --city Denver
```

Omit the location options for the interactive selector, provide a positional
query to seed fuzzy matching, or use `--country` to restrict the selector.

The default candidate budget is 12. Use `--max-candidates`, `--refresh`, or
`--full` to change the budget, request current inventory, or add the default ping
and DNS checks. `--ping`, `--resolve`, and `--dns-server` override check targets.

`--ping` and `--resolve` are repeatable. Any custom check option enables full
checks. Supplied ping or name values replace that category's default; omitted
categories retain the defaults documented below. `Ctrl-c` stops new scheduling,
waits for active probes, and exits without export.

Color defaults to interactive terminals only and honors `NO_COLOR`. Override it
with `--color auto|always|never`. Phase progress goes to standard error;
selection, confirmation, and export paths go to standard output. `find` returns
nonzero if it confirms no endpoint, is cancelled, or cannot export.

### Inventory Only

List tab-separated country, city, and candidate counts without reading a key or
probing endpoints:

```sh
cargo run -p nordprobe --release -- cities --country "United States"
```

Country matching is case-insensitive and exact. No match, unusable inventory, or
an API failure returns a nonzero status. `cities` fetches live inventory directly
and does not use the TUI and `find` cache.

## Probe Behavior

The TUI defaults to a confirmation goal of 3 and a candidate budget of 12. The
goal can be 1 through 10 and the budget up to 100, bounded by available
candidates:

```text
confirmation goal <= candidate budget <= available candidates
```

Candidates are ordered by reported load and hostname while sampling distinct
IPv4 `/24` prefixes before repeating one. Candidates sharing a server public key
form one pacing group. Nordprobe permits one active attempt per group, four
groups globally, and at least six seconds between handshake starts using the
same server key.

Each candidate is attempted once. Scheduling stops at the confirmation goal,
candidate budget, or cancellation request. Each attempt has a nine-second
overall deadline and no retry. `Esc` requests cooperative TUI cancellation and
waits for active attempts; `q` or `Ctrl-c` exits the TUI immediately. No
installed tunnel or session remains.

## Evidence and Full Checks

| Result | Meaning |
| --- | --- |
| `CONFIRMED` | The tested identity authenticated the tested server key at the endpoint. |
| `UNCONFIRMED` | No authenticated response arrived; silence is inconclusive. |
| `ERROR` | Local validation, socket, I/O, protocol, or worker processing failed. |

Handshake-only mode is the default. Full checks always use the listed inner
address and route. The TUI and `find --full` use the listed check targets unless
`find` overrides them:

```text
Address:    10.5.0.2/32
DNS:        103.86.96.100
AllowedIPs: 0.0.0.0/0
Ping:       1.1.1.1
Resolve:    example.com
```

A passed ping or DNS check confirms only that packet exchange. It does not
establish a system VPN or prove general connectivity.

## Inventory and Cache

Nordprobe requests unauthenticated metadata from
`https://api.nordvpn.com/v1/servers`. It retains online WireGuard records,
validates required fields, and removes duplicate endpoint/key pairs. Decoded
responses are limited to 64 MiB; malformed records are skipped, while an invalid
document fails the request. The inventory API provides no token or private key.

API status and load are selection hints, not authentication evidence.

Normalized inventory is stored as `nordprobe/inventory.json` under the platform
cache directory, commonly `~/.cache` on Linux or `~/Library/Caches` on macOS.
Inventory becomes stale after one day but remains usable and is not refreshed
automatically. Use `Ctrl-r` in the TUI or `find --refresh`. Failed refreshes keep
the existing cached or in-memory inventory.

The blocking HTTPS operation runs in a worker but cannot itself be cancelled.
Leaving the loading screen discards its eventual result.

## Export

**Warning:** Every export contains the private key in plaintext. Protect it like
the source private-key file.

The default directory is `./nordprobe-exports`. It is created on the first
export, and displayed paths preserve whether the configured path was relative or
absolute. Only confirmed results belonging to the pinned run identity can be
exported.

Generated configurations set address `10.5.0.2/32`, Nord DNS servers,
`AllowedIPs = 0.0.0.0/0`, and `PersistentKeepalive = 25`.

Nordprobe sanitizes filenames and uses numeric suffixes instead of overwriting
files. On Unix, newly created directories use mode `0700` and files use `0600`;
existing directory permissions are preserved. Setup resolves existing symlink
components, and export rejects components replaced by symlinks afterward.

These checks prevent ordinary path mistakes, not replacement by a hostile local
process with access to writable parent directories. Failed writes remove partial
files; a cleanup failure reports the path and warns that key material can remain.
