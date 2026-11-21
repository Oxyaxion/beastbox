# Install

Requirements: FreeBSD 15, ZFS (extended attributes required), a reverse proxy for TLS, the clock kept on time
(`sysrc ntpd_enable=YES`: two-step verification codes allow 30 s of drift). Commands run as root.
Single sign-on is optional and per tenant: see [Single sign-on](#single-sign-on-oidc) below.

```sh
pw useradd beastbox -d /nonexistent -s /usr/sbin/nologin
# Built binary (FreeBSD 15 amd64), from the release page: the archive and its .sha256
sha256sum -c beastbox-X.Y.Z-freebsd15-amd64.tar.xz.sha256 && tar -xf beastbox-X.Y.Z-freebsd15-amd64.tar.xz
cd beastbox-X.Y.Z-freebsd15-amd64 && install -m 0555 beastbox /usr/local/bin/ && install -m 0555 rc.d/beastbox /usr/local/etc/rc.d/
# Or from the sources: cargo build --release --locked, then target/release/beastbox and rc/beastbox

# One dataset per tenant, one child per user (quota = their space)
zfs create -o mountpoint=none -o canmount=off -o xattr=sa -o compression=lz4 -o atime=off -o exec=off -o setuid=off zroot/beastbox
zfs create -o mountpoint=/mnt/data/beastbox-alpha zroot/beastbox/alpha
zfs create -o quota=50G zroot/beastbox/alpha/alice
chown -R beastbox:beastbox /mnt/data/beastbox-alpha && chmod 0700 /mnt/data/beastbox-alpha /mnt/data/beastbox-alpha/alice

install -m 0640 -g beastbox beastbox.example.toml /usr/local/etc/beastbox.toml   # adapt it (commented)
su -m beastbox -c 'beastbox check-config'
su -m beastbox -c 'beastbox user add --tenant alpha alice --admin'               # password shown once
sysrc beastbox_enable=YES && service beastbox start                              # log: /var/log/beastbox/
```

## Reverse proxy (nginx)
```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Real-IP $remote_addr;      # overwrites the client's value
    proxy_set_header X-Forwarded-Host "";
    proxy_request_buffering off;
    proxy_buffering off;
    client_max_body_size 0;
}
```
Behind an SSO, exempt: `/status.php`, `/index.php/204`, `/index.php/login/v2`, `/index.php/core/preview`, `/remote.php/`, `/ocs/`, `/s/`.

## Single sign-on (OIDC)

One provider per tenant, in the tenant's block. Nothing to install on the host: the back channel goes through the
Casper `system.net` service of the base system (`libcasper`, a forked child of the process), limited at startup to
the configured destinations; `serve` refuses to start when that channel cannot be opened or verified (ADR-6 in
`docs/dev/DEPS.md`).

```toml
[[tenant]]
name = "alpha"
hosts = ["files.alpha.example", "*.alpha.example"]
data_root = "/mnt/data/beastbox-alpha"

[tenant.oidc]
issuer = "https://auth.example/application/o/beastbox/"   # byte for byte, trailing slash included
client_id = "beastbox-alpha"
client_secret_file = "/etc/beastbox-alpha-oidc.secret"    # read once at startup, never printed
second_factor = "beastbox"        # or "provider": who holds the account's second factor
public_base_url = "https://files.alpha.example:8443"      # only when TLS does not end on 443
# password_login = false          # the Beastbox password form is gone by default: the provider is the way in
# ca_file, connect_addr, backchannel_hosts, required_amr: see beastbox.example.toml
```

Provider side: a **confidential** client, authorization code + PKCE (S256), `client_secret_basic`, scopes
`openid`, redirect URI `<public_base_url or https://<first exact host of the tenant>>/login/oidc/callback`.
Beastbox reads the `id_token` only, and trusts TLS (no JWT signature check): point `ca_file` at the bundle that
covers the provider.

- **Second factor.** `second_factor = "beastbox"` (default): the provider authenticates, then Beastbox asks the
  account's own TOTP if it has one. `"provider"`: the provider does both and Beastbox checks `required_amr`
  (default `["mfa"]`); empty `required_amr` means the provider's policy is trusted, warned at startup.
- **Who signs in.** An account is bound to a provider identity **by the administrator only**:
  `beastbox user add --tenant alpha bob --oidc` (no password), then
  `beastbox user oidc-link --tenant alpha bob --subject <sub the provider gives for that account>`. Linking clears
  the account's password and ends its sessions; `beastbox user passwd` undoes it (identity removed, sessions ended).
- **One door.** On a tenant with a provider the web sign-in form is **gone** and `POST /login` is refused: the
  provider is the only way in, then the account's TOTP when Beastbox holds it. `password_login = true` keeps the
  local form for a break-glass account — and leaves a second, weaker door open. `beastbox user passwd` on such a
  tenant therefore opens nothing by itself.
- **When it does not work.** `issuer` must match the provider's `iss` byte for byte (a trailing slash or a path
  counts); the jail must reach `https://<issuer host>` (system DNS, or `connect_addr` for split DNS); the
  redirect URI registered at the provider must be exactly the one above; the log says which check refused
  (`oidc callback refused: …`), and every refusal counts in the login's rate limit.

## Commands
```sh
beastbox user add --tenant T NAME [--admin]   # create the dataset <data_root>/NAME first; password chosen at first sign-in
beastbox user list --tenant T                  # name, role, active|disabled, 2fa|-
beastbox user disable --tenant T NAME          # no sign-in, sessions ended, devices and links blocked; files kept
beastbox user enable --tenant T NAME           # devices and links answer again
beastbox user 2fa-reset --tenant T NAME        # lost phone and recovery codes: two-step verification removed, sessions ended
beastbox user passwd --tenant T NAME           # stdin; empty = generated (recommended); to be replaced at next sign-in
beastbox user add --tenant T NAME --oidc       # dataset first; no password: signs in through the provider only
beastbox user oidc-link --tenant T NAME --subject S   # binds the provider identity S (its `sub`) to that account
beastbox verify --tenant T [--user U]         # read-only; exit code 1 if there are discrepancies
beastbox rescan --tenant T [--user U] [--readers N]   # after a change made outside Beastbox (N: files read at once)
beastbox manifest --tenant T [--user U]       # before every backup (see backup.md)
beastbox restore --tenant T --user U --from DIR --path P [--to Q]   # past version, never overwrites (backup.md)
beastbox -h | -V                               # help (every command) | version
```
Useful settings: `read_only = true` (maintenance), `trash_days`, `share_history_days`, `min_free_bytes`; drop links:
`drop_max_file_bytes` (1 GiB), `drop_max_total_bytes` (10 GiB) and `drop_max_files` (500) per link.
