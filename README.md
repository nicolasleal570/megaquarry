# megaquarry

Download and upload MEGA files from your terminal: parallel, resumable, and scriptable.

megaquarry lists and downloads public MEGA links (files and folders), uploads to
your account, and keeps every transfer in a queue that survives restarts and
Ctrl-C. Optionally, it can switch to a new exit IP through a VPN when MEGA's
download quota runs out.

## Install

Requires Rust 1.85 or newer. No system libraries needed (rustls for TLS, SQLite is bundled).

```sh
cargo install --git https://github.com/nicolasleal570/megaquarry megaquarry-cli
megaquarry --version
```

To build from source instead:

```sh
git clone https://github.com/nicolasleal570/megaquarry
cd megaquarry
cargo build --release
./target/release/megaquarry --help
```

## Quick start

```sh
# 1. See what a public link contains
megaquarry ls 'https://mega.nz/folder/XXXX#KEY'

# 2. Download it into ~/Downloads (without -o, files go to the current folder)
megaquarry download 'https://mega.nz/folder/XXXX#KEY' -o ~/Downloads

# 3. Interrupted? Ctrl-C keeps unfinished files in the queue. Continue later with:
megaquarry queue run
```

Keep links in quotes so your shell leaves the `#KEY` part alone.

## Usage

Every command has `--help`; `download`, `ls`, `upload` and `queue` end their
help with examples.

### Links and downloads

`ls` and `download` accept file, folder, subfolder and file-inside-a-folder
links, in the current, legacy and `mega://` forms.

```sh
megaquarry ls 'https://mega.nz/folder/XXXX#KEY'
megaquarry download 'https://mega.nz/file/XXXX#KEY' -o ~/Downloads
```

`ls` prints human-readable sizes (`1.4 GiB`) and a total line such as
`12 file(s), 48.2 GiB`; `ls --json` gives exact bytes. Without `-o`, files go
to the `download_dir` setting, which defaults to the current folder.

### Accounts

```sh
megaquarry login you@example.com                  # password from MEGAQUARRY_PASSWORD or a prompt
megaquarry login you@example.com --mfa 123456     # with a two-factor code
megaquarry accounts
megaquarry logout you@example.com
```

Only the derived key is stored, never the password. To encrypt stored
accounts at rest, set a master password:

```sh
megaquarry master-password set       # new password from MEGAQUARRY_NEW_MASTER_PASSWORD or a prompt
megaquarry master-password remove    # asks for confirmation; --yes skips it
```

When a master password is set, commands that need an account read it from
`MEGAQUARRY_MASTER_PASSWORD` or prompt for it.

To download through an account instead of anonymously, set
`download_account` (see [Configuration](#configuration)).

### Uploads

```sh
megaquarry upload ./photos                              # when only one account is stored
megaquarry upload ./photos --account you@example.com    # choose an account
megaquarry upload ./report.pdf --to FOLDER_HANDLE       # into a folder (default: Cloud Drive)
megaquarry upload ./photos --public-link                # print a public link for each file
```

`--account` is optional when exactly one account is stored. With none, the
error tells you to run `megaquarry login EMAIL` first; with several, it lists
them and asks for `--account EMAIL`.

Uploaded files are private by default. `--public-link` creates and prints a
public link for each uploaded file; the setting `upload_public_links yes` does
it for every upload.

### The queue

Every download and upload goes through a persistent queue. Ctrl-C stops the
run and keeps unfinished transfers; `queue run` continues them.

```sh
megaquarry download --no-start 'https://mega.nz/folder/XXXX#KEY'   # only add to the queue
megaquarry queue list
megaquarry queue run
megaquarry queue pause ID      # keep an entry without running it
megaquarry queue resume ID     # let a paused or failed entry run again
megaquarry queue retry         # let every failed entry run again
megaquarry queue remove ID
```

Queued uploads need an account to run: `megaquarry queue run --account you@example.com`.

Only one transferring command (`download`, `upload`, `queue run`) runs at a
time per data directory; a second one exits with code 3 without touching the
queue. Read-only commands (`ls`, `queue list`, `config`) and
`download --no-start` keep working meanwhile.

## Configuration

Settings live in the database in the data directory.

```sh
megaquarry config list                          # every setting with its value
megaquarry config get max_downloads
megaquarry config set download_speed_limit 500  # KiB/s
megaquarry config unset download_speed_limit    # back to the default
```

| Setting | Default | Allowed values | Meaning |
|---|---|---|---|
| `download_dir` | `.` | a folder path | Folder downloads are saved in (`-o` overrides it) |
| `download_connections` | `6` | 1 to 20 | Connections per download; `1` is single-connection mode |
| `max_downloads` | `4` | 1 to 50 | Downloads running at once |
| `upload_connections` | `6` | 1 to 20 | Connections per upload |
| `max_uploads` | `4` | 1 to 50 | Uploads running at once |
| `verify_downloads` | `yes` | `yes` or `no` | Check each file's MAC after downloading |
| `download_speed_limit` | `0` | 0 or more | Total download speed limit in KiB/s; `0` is unlimited |
| `upload_speed_limit` | `0` | 0 or more | Total upload speed limit in KiB/s; `0` is unlimited |
| `upload_public_links` | `no` | `yes` or `no` | Create and print a public link for each uploaded file |
| `download_account` | empty | a stored account email | Account to download through; empty downloads anonymously |
| `app_key` | empty | text | Custom MEGA application key |
| `egress_cooldown_fallback` | `3600` | 60 to 86400 | Seconds an exit IP rests after a quota hit when MEGA gives no wait |
| `egress_max_attempts` | `5` | 1 to 20 | VPN reconnects per rotation before waiting |
| `egress_reconnect_timeout` | `90` | 1 to 600 | Seconds to wait for the VPN after a reconnect |

`config set` rejects invalid values with exit code 2 and says what is
allowed, for example:

```text
error: max_downloads must be a number from 1 to 50 (got "abc")
error: verify_downloads must be yes or no (got "true")
```

If the database already holds an invalid value, megaquarry prints a
`warning: ...` on stderr when it starts and uses the default instead (a number
out of range is clamped to the nearest allowed value).

The setting names changed before the first release: for example
`default_down_dir` is now `download_dir`, and `limit_download_speed` plus
`max_download_speed` became `download_speed_limit`. Old names are not
migrated; set the new ones again.

### Environment variables

| Variable | Purpose |
|---|---|
| MEGAQUARRY_HOME | Data directory, also `--home` (default: platform data dir + `megaquarry`) |
| MEGAQUARRY_PASSWORD | Account password for `login` |
| MEGAQUARRY_MASTER_PASSWORD | Unlocks stored accounts when a master password is set |
| MEGAQUARRY_NEW_MASTER_PASSWORD | New password for `master-password set` |
| MEGAQUARRY_EGRESS_URL | gluetun control server URL; enables exit IP rotation (`--egress-url`) |
| MEGAQUARRY_EGRESS_KEY_FILE | File with the gluetun control API key (`--egress-key-file`) |

`--egress-url` and `--egress-key-file` are accepted only by `download` and
`queue run`.

## Exit codes and scripting

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error |
| 2 | Bad usage or invalid value |
| 3 | Another transfer is already running |
| 4 | The run finished, but some transfers failed |
| 130 | Interrupted (Ctrl-C) |

Results go to stdout; progress, warnings and errors go to stderr. In a
terminal, each transfer shows a progress bar. Otherwise (pipes, logs) only
`[id] started ...`, `[id] <summary>` and `[id] failed: ...` lines appear.
`-q` or `--quiet` hides progress and started lines but keeps errors,
warnings, results and the final summary.

These commands print one JSON document to stdout with `--json`:

| Command | Shape |
|---|---|
| `ls --json` | `{"files": [{"path", "name", "size", "link"}], "count", "total_size"}` |
| `queue list --json` | `{"entries": [{"id", "kind", "state", "target", "error"}]}`; `kind` is `"download"` or `"upload"`, `error` is a string or `null` |
| `accounts --json` | `{"accounts": [{"email"}]}` |
| `config list --json` | `{"settings": [{"key", "value", "default", "is_default", "description"}]}`; values are strings |
| `config get KEY --json` | One object with the same fields as a `config list` entry |

Sizes are whole bytes and ids are numbers. Fields may be added in later
versions but are not renamed.

```sh
# Ids of the failed queue entries
megaquarry queue list --json | jq '.entries[] | select(.state == "failed") | .id'
```

## Shell completions

```sh
megaquarry completions bash > ~/.local/share/bash-completion/completions/megaquarry
megaquarry completions zsh > "${fpath[1]}/_megaquarry"
megaquarry completions fish > ~/.config/fish/completions/megaquarry.fish
```

Open a new shell afterwards.

## Exit IP rotation with Docker (gluetun, Surfshark)

MEGA limits how much one IP may download. With rotation enabled, a download
that hits the limit (HTTP 509) does not fail: megaquarry marks the exit IP as
resting for as long as MEGA asks (`X-MEGA-Time-Left`, 1 hour when MEGA does
not say), asks [gluetun](https://github.com/qdm12/gluetun) to reconnect to
another Surfshark server, skips IPs that are still resting (up to 5
reconnects), fetches a fresh download link and carries on. When every IP tried
is resting, or gluetun does not answer, downloads wait and retry every 60 s.
Resting IPs are kept in the database, so they survive restarts.

Rotating IPs to avoid the quota goes against MEGA's terms of service.

`compose.yaml` runs two containers: `vpn` (gluetun, the only one with
`NET_ADMIN`) and `megaquarry` (unprivileged, uid 1000), which shares the
`vpn` container's network. megaquarry's only way out is the tunnel: while it
is down there is no network at all, so nothing is downloaded over your real
IP, and the rest of the machine never goes through the VPN.

### Setup 

```sh
# 1. Surfshark "manual setup" credentials (not your account email/password):
#    Surfshark dashboard > VPN > Manual setup > OpenVPN > Credentials.
mkdir -p secrets
printf '%s' 'SERVICE_USERNAME' > secrets/openvpn_user
printf '%s' 'SERVICE_PASSWORD' > secrets/openvpn_password

# 2. An API key for gluetun's control server, shared by both containers.
key=$(docker run --rm qmcgaw/gluetun:v3.41.3 genkey)
printf '%s' "$key" > secrets/gluetun_api_key
sed "s/REPLACE_WITH_API_KEY/$key/" gluetun/config.toml.example > gluetun/config.toml
chmod 600 secrets/* gluetun/config.toml

# 3. Build the image on this machine (arm64 on Apple Silicon).
docker compose build
```

`secrets/` and `gluetun/config.toml` are git-ignored. On OrbStack the
containers can read these `0600` files; on a Linux Docker host, give
`secrets/gluetun_api_key` to uid 1000 instead
(`sudo chown 1000 secrets/gluetun_api_key`), since Compose ignores `uid` and
`mode` for file secrets. Without `gluetun/config.toml`, gluetun v3.41.3
leaves its control routes open, and megaquarry refuses to start. Optional
variables: `SURFSHARK_COUNTRIES` (e.g. `Netherlands,Germany`; empty means
all), `MEGAQUARRY_DATA` (default `./data`) and `MEGAQUARRY_DOWNLOADS`
(default `./downloads`).

### Daily use

```sh
docker compose run --rm megaquarry download 'https://mega.nz/folder/XXXX#KEY'
docker compose run --rm megaquarry queue list
docker compose logs vpn          # if the VPN does not come up
docker compose down              # stops the VPN (it keeps running otherwise)
```

The output shows each rotation, for example
`quota hit on 185.x.x.x, rotating…` then `now on 89.x.x.x (cooling: 3)`,
where `cooling` counts the IPs still resting ("cooling down" and "resting" are
the same state).

At startup megaquarry checks that the control server requires the key,
starts the VPN if a cancelled rotation left it stopped, waits for the tunnel
and moves away from a resting IP.

Downloads through an account (the `download_account` setting, or
`queue run --account`) never rotate: an account's quota is not tied to the IP.

Three settings tune rotation: `egress_cooldown_fallback`,
`egress_max_attempts` and `egress_reconnect_timeout` (see
[Configuration](#configuration)). If the VPN does not come up, see
[Troubleshooting](#the-vpn-restarts-in-a-loop).

### Manual check on the target machine

Automated tests use fakes of MEGA and gluetun; these need the real thing:

1. `docker run --rm --cap-add=NET_ADMIN --device /dev/net/tun alpine ls -l /dev/net/tun`
   lists the device (TUN works for gluetun).
2. `docker compose up -d vpn && docker compose logs vpn` reaches
   `Initialization Sequence Completed` with a Surfshark public IP.
3. `docker compose exec vpn wget -O- http://127.0.0.1:8000/v1/vpn/status`
   is refused with `401 Unauthorized` (no key sent; wget exits with 6). A
   `200 OK` with `{"status":"running"}` means the control routes are open.
4. A download larger than the quota finishes on its own; note how long a
   reconnect takes (tunes `egress_reconnect_timeout`) and whether MEGA's 509
   carries `X-MEGA-Time-Left`.
5. Downloaded files in `./downloads` belong to your user and are written at a
   reasonable speed through the bind mount.

## Troubleshooting

### Another transfer is already running (exit code 3)

Only one `download`, `upload` or `queue run` runs at a time per data
directory. Wait for the other one to finish, or stop it with Ctrl-C; its
unfinished transfers stay queued. Meanwhile you can still add links with
`download --no-start`.

### Two-factor login

Pass the code with `megaquarry login you@example.com --mfa 123456`. Without
`--mfa`, megaquarry asks for the code on a terminal.

### No terminal for the password

Scripts, cron jobs and containers have no terminal to prompt on. Set the
password in the environment instead: `MEGAQUARRY_PASSWORD` for `login`,
`MEGAQUARRY_MASTER_PASSWORD` to unlock stored accounts, and
`MEGAQUARRY_NEW_MASTER_PASSWORD` for `master-password set`. For two-factor
codes, pass `--mfa`.

### Quota hit without rotation

Without exit IP rotation, a download that hits MEGA's quota (HTTP 509) waits
about a minute and retries a few times, then is marked failed; the run ends
with exit code 4. MEGA's wait can last hours. Your options:

- Wait, then run `megaquarry queue retry` and `megaquarry queue run`.
- Download through an account (`config set download_account you@example.com`).
- Set up [exit IP rotation with Docker](#exit-ip-rotation-with-docker-gluetun-surfshark).

### The VPN restarts in a loop

If `docker compose logs vpn` shows `Initialization Sequence Completed` and
then `restarting VPN because it failed to pass the healthcheck ... running TLS
handshake: context deadline exceeded` in a loop, packets are too large for the
path. `compose.yaml` sets `OPENVPN_MSSFIX=1320` for that (needed on OrbStack);
try a lower value (`OPENVPN_MSSFIX=1200 docker compose up -d vpn`) or TCP
(`OPENVPN_PROTOCOL: tcp` in `compose.yaml`).

The `block-outside-dns` error in the same log is harmless (a Windows-only
option Surfshark pushes to every client).

### megaquarry refuses to start in Docker

megaquarry checks at startup that gluetun's control server requires the API
key. If it does not, create `gluetun/config.toml` as in
[Setup](#setup-macos-with-orbstack-or-any-docker-host); step 3 of the
[manual check](#manual-check-on-the-target-machine) confirms it.

## Development

```sh
cargo test --workspace
```

Tests need no network and no MEGA account: they run against local fakes of
the MEGA API, the storage servers and gluetun's control server.
`tools/gen_vectors.py` produces reference vectors from an independent
implementation, which the tests check against.

Layout:

- `crates/megaquarry-core`: the library, organized by feature: `crypto`,
  `link`, `chunk`, `api` (client + hashcash), `public` (public links),
  `session` (login), `download`, `upload`, `queue`, `store` (SQLite),
  `egress` (exit IP rotation), and `adapters` (reqwest HTTP, gluetun control).
  Network access goes through port traits (`ApiTransport`,
  `DownloadTransport`, `UploadTransport`, `TransferRunner`, `VpnControl`).
- `crates/megaquarry-cli`: the `megaquarry` binary.
- `tools/gen_vectors.py`: reference vectors from an independent implementation.

## Security notes and limitations

- Passwords are never stored (only the derived key and user hash), and stored
  secrets use authenticated encryption; the database is private to the user.
- Uploaded files get no public link unless you ask for one (`--public-link`
  or `upload_public_links yes`).
- Error codes follow the MEGA SDK numbering.
- Uploads post to `url/offset` (MEGA SDK form) and resume from confirmed chunks.
- Known limitation: queued transfers keep their file keys (download links,
  upload checkpoints) in the database unencrypted; the master password
  protects account credentials and sessions only. The database file is
  readable by its owner only.
- Quota hits rotate the VPN exit IP through gluetun only when rotation is set
  up (see [Exit IP rotation](#exit-ip-rotation-with-docker-gluetun-surfshark)).
- Not supported yet: MegaCrypter, ELC/DLC containers, a streaming
  server, split/merge, thumbnails, clipboard monitoring, and the GUI.

## License

Licensed under either of

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this work, as defined in the Apache-2.0 license,
shall be dual licensed as above, without any additional terms or conditions.
