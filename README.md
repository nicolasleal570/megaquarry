# megaquarry

A MEGA client written in Rust: API client, crypto, parallel chunked downloads
and uploads and a persistent transfer queue, with a command-line interface on
top. A GUI can be added later as another adapter over the same core.

> Status: tested against local fakes of the MEGA API and storage servers and
> against reference vectors from an independent implementation; **not yet
> exercised against the live MEGA service**.

## Build

```sh
cargo build --release
./target/release/megaquarry --help
```

No system libraries are needed (rustls for TLS, bundled SQLite).

## Usage

```sh
# Public links (file, folder, subfolder, file inside a folder, legacy and mega:// forms)
megaquarry ls 'https://mega.nz/folder/XXXX#KEY'
megaquarry download 'https://mega.nz/file/XXXX#KEY' -o ~/Downloads

# Accounts (the password is read from MEGAQUARRY_PASSWORD or prompted)
megaquarry login you@example.com
megaquarry upload ./photos --account you@example.com

# The queue survives restarts; Ctrl-C stops and keeps unfinished transfers
megaquarry download --no-start LINK...
megaquarry queue list
megaquarry queue run
megaquarry queue pause ID | resume ID | retry | remove ID

# Settings
megaquarry config list
megaquarry config set max_downloads 2
megaquarry config set limit_download_speed yes
megaquarry config set max_download_speed 500   # KiB/s

# Encrypt stored accounts at rest
megaquarry master-password set                 # or MEGAQUARRY_NEW_MASTER_PASSWORD
```

| Environment variable | Purpose |
|---|---|
| `MEGAQUARRY_HOME` | Data directory (default: platform data dir + `megaquarry`) |
| `MEGAQUARRY_PASSWORD` | Account password for `login` |
| `MEGAQUARRY_MASTER_PASSWORD` | Unlocks stored accounts when a master password is set |
| `MEGAQUARRY_NEW_MASTER_PASSWORD` | New password for `master-password set` |
| `MEGAQUARRY_EGRESS_URL` | gluetun control server URL; enables exit IP rotation (`--egress-url`) |
| `MEGAQUARRY_EGRESS_KEY_FILE` | File with the gluetun control API key (`--egress-key-file`) |

Only one transferring command (`download`, `upload`, `queue run`) runs at a
time per data directory; a second one exits at once without touching the
queue. Read-only commands (`ls`, `queue list`, `config`) and
`download --no-start` keep working meanwhile.

## Exit IP rotation (Docker, gluetun, Surfshark)

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

### Setup (macOS with OrbStack, or any Docker host)

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
`mode` for file secrets. Without
`gluetun/config.toml`, gluetun v3.41.3 leaves its control routes open, and
megaquarry refuses to start. Optional variables: `SURFSHARK_COUNTRIES`
(e.g. `Netherlands,Germany`; empty means all), `MEGAQUARRY_DATA` (default
`./data`) and `MEGAQUARRY_DOWNLOADS` (default `./downloads`).

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
the same state; `egress_cooldown_fallback` sets how long it lasts when MEGA
does not say).

At startup megaquarry checks that the control server requires the key,
starts the VPN if a cancelled rotation left it stopped, waits for the tunnel
(within `egress_reconnect_timeout`) and moves away from a resting IP.

Downloads through an account (`use_mega_account_down`, or
`queue run --account`) never rotate: an account's quota is not tied to the IP.

| Setting | Default | Meaning |
|---|---|---|
| `egress_cooldown_fallback` | 3600 | Seconds an IP rests when MEGA gives no wait |
| `egress_max_attempts` | 5 | Reconnects per rotation before waiting |
| `egress_reconnect_timeout` | 90 | Seconds to wait for the tunnel after a reconnect |

If `docker compose logs vpn` shows `Initialization Sequence Completed` and
then `restarting VPN because it failed to pass the healthcheck ... running TLS
handshake: context deadline exceeded` in a loop, packets are too large for the
path. `compose.yaml` sets `OPENVPN_MSSFIX=1320` for that (needed on OrbStack);
try a lower value (`OPENVPN_MSSFIX=1200 docker compose up -d vpn`) or TCP
(`OPENVPN_PROTOCOL: tcp` in `compose.yaml`). The
`block-outside-dns` error in the same log is harmless (a Windows-only option
Surfshark pushes to every client).

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

## Layout

- `crates/megaquarry-core` — the library, organized by feature: `crypto`,
  `link`, `chunk`, `api` (client + hashcash), `public` (public links),
  `session` (login), `download`, `upload`, `queue`, `store` (SQLite),
  `egress` (exit IP rotation), and `adapters` (reqwest HTTP, gluetun control).
  Network access goes through port traits (`ApiTransport`,
  `DownloadTransport`, `UploadTransport`, `TransferRunner`, `VpnControl`).
- `crates/megaquarry-cli` — the `megaquarry` binary.
- `tools/gen_vectors.py` — reference vectors from an independent implementation.

## Security notes and limitations

- Passwords are never stored (only the derived key and user hash), and stored
  secrets use authenticated encryption; the database is private to the user.
- Error codes follow the MEGA SDK numbering.
- Uploads post to `url/offset` (MEGA SDK form) and resume from confirmed chunks.
- Known limitation: queued transfers keep their file keys (download links,
  upload checkpoints) in the database unencrypted;
  the master password protects account credentials and sessions only. The
  database file is readable by its owner only.
- Quota hits rotate the VPN exit IP through gluetun (see above).
- Not supported yet: MegaCrypter, ELC/DLC containers, a streaming
  server, split/merge, thumbnails, clipboard monitoring, and the GUI.
