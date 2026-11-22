//! TOML configuration (example: `beastbox.example.toml`).

use crate::{Error, Result};
use serde::Deserialize;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Listen address (§0.3): loopback by default, never the unspecified address.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// The only addresses whose connections are accepted (the reverse proxy).
    pub trusted_proxies: Vec<IpAddr>,
    /// SQLite database, keys and state journals.
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// Runtime threads: fixed and small (§0.4).
    #[serde(default = "default_workers")]
    pub worker_threads: usize,
    #[serde(default = "default_blocking")]
    pub blocking_threads: usize,
    /// Concurrent connections (§0.4, §0.5); beyond that, new ones are closed right away.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Nextcloud version announced to clients (`major.minor.micro`). Raise it when a recent client
    /// refuses or flags a server as too old; changes nothing in the server's behavior.
    #[serde(default = "default_nc_version")]
    pub nextcloud_version: String,
    /// Read-only (maintenance, incident): every write answers 503 (§0.2).
    #[serde(default)]
    pub read_only: bool,
    /// Free-space reserve on a tenant's dataset: below it, its writes answer 503 (read-only)
    /// instead of failing at random (§0.2).
    #[serde(default = "default_min_free")]
    pub min_free_bytes: u64,
    /// Cleartext HTTP test bench only: cookies without `Secure` or the `__Host-` prefix (browsers refuse
    /// a `Secure` cookie outside HTTPS). **Never in production**: disabled by default, flagged at startup.
    #[serde(default)]
    pub insecure_cookies: bool,
    /// Drop links (§8): maximum size of a dropped file and total volume per link.
    #[serde(default = "default_drop_file")]
    pub drop_max_file_bytes: u64,
    #[serde(default = "default_drop_total")]
    pub drop_max_total_bytes: u64,
    /// Drop links: maximum number of files received per link.
    #[serde(default = "default_drop_files")]
    pub drop_max_files: u32,
    /// Trash (§6): days before automatic permanent deletion (0 = never).
    /// shortcut: global setting; per tenant (§6) when a tenant needs it.
    #[serde(default = "default_trash_days")]
    pub trash_days: u32,
    /// Public link history (downloads, drops, refused passwords): days of retention.
    #[serde(default = "default_share_history_days")]
    pub share_history_days: u32,
    /// Minimum length of a chosen human password (web and `user passwd`); never below 10.
    #[serde(default = "default_min_password")]
    pub min_password: usize,
    #[serde(rename = "tenant")]
    pub tenants: Vec<TenantConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantConfig {
    pub name: String,
    pub hosts: Vec<String>,
    pub data_root: PathBuf,
    /// Two-step verification (TOTP) for the tenant's accounts.
    #[serde(default)]
    pub two_factor: TwoFactor,
    /// The tenant's public address for the links the CLI prints (activation), `scheme://host[:port]`: `https`, or `http`
    /// on a test bench (`insecure_cookies`); one of the tenant's hosts. Default: `https://` + its first exact host.
    #[serde(default)]
    pub public_base_url: Option<String>,
    /// Single sign-on: absent means the tenant's accounts sign in with a password only.
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
}

/// `[tenant.oidc]`: Beastbox is a confidential client (authorization code + PKCE S256). Design and reasons:
/// `docs/dev/oidc-proposal.md`.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    /// The provider's issuer, exactly as it publishes it (trailing slash and path included): compared byte for byte.
    pub issuer: String,
    pub client_id: String,
    pub client_secret_file: PathBuf,
    /// Who signs the second factor in (§7): Beastbox asks its TOTP code, or the provider handles it.
    #[serde(default)]
    pub second_factor: SecondFactor,
    /// `amr` values accepted as a second factor, with `second_factor = provider` on a `required` tenant.
    #[serde(default = "default_amr")]
    pub required_amr: Vec<String>,
    /// Fixed TLS endpoint instead of DNS (provider on the LAN, split DNS).
    pub connect_addr: Option<SocketAddr>,
    /// Other hosts the token endpoint may live on (`host` or `host:port`), at most 8.
    #[serde(default)]
    pub backchannel_hosts: Vec<String>,
    /// Roots of the provider's certificate (a private CA, or the system bundle).
    #[serde(default = "default_ca")]
    pub ca_file: PathBuf,
    /// Public base URL of `redirect_uri` when TLS does not end on port 443 (test bench behind a port
    /// redirect, or a provider fronted on a non-standard port). Optional: without it, the base is
    /// `https://<first exact host of the tenant>`. Like the hosts, it comes from the configuration only,
    /// never from a request's `Host` header (§4.1); its host must be one of the tenant's hosts.
    #[serde(default)]
    pub public_base_url: Option<String>,
    /// Keep the Beastbox password form for the web sign-in. **Off by default** on a tenant with a provider: the
    /// provider is then the only way in, and the account's own TOTP (when it has one) comes after. Set it to
    /// `true` for a break-glass account, remembering that local passwords then stay a second door.
    #[serde(default)]
    pub password_login: bool,
}

/// `beastbox` (default): the provider signs the user in, Beastbox asks its TOTP code; `provider`: the provider
/// does both, Beastbox asks nothing.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecondFactor {
    #[default]
    Beastbox,
    Provider,
}

/// `[tenant.oidc]` parsed and ready at runtime: the client secret is read **once at startup** (before Capsicum,
/// while paths are still allowed) and the public base URL comes from the configured hosts — never from a
/// request's `Host` header, so `redirect_uri` cannot be reopened by a forged header (§4.1).
#[derive(Debug)]
pub struct OidcRuntime {
    pub client: crate::auth::oidc::OidcClient,
    /// Client secret (bounded, visible ASCII without `:` so the Basic header stays unambiguous).
    pub secret: String,
    pub second_factor: SecondFactor,
    pub required_amr: Vec<String>,
    /// Fixed TLS endpoint instead of DNS (provider on the LAN, split DNS).
    pub connect_addr: Option<SocketAddr>,
    /// TLS client built from `ca_file` **at startup**: after `cap_enter()` an absolute path can no longer
    /// be opened, so it is read once, like the secret.
    pub tls: std::sync::Arc<rustls::ClientConfig>,
    /// `https://<first exact host of the tenant>`: the base of `redirect_uri`, from the configuration only.
    pub base: String,
    /// [`OidcConfig::password_login`]: the Beastbox password form stays open beside the provider.
    pub password_login: bool,
    /// Discovery document, fetched once over the back channel and kept (a restart re-reads it). `None` until
    /// the first sign-in; `Err(when)` after a failed fetch, retried once `web::oidc::DISCOVERY_RETRY` has passed.
    pub discovery: std::sync::Mutex<Option<std::result::Result<crate::auth::oidc::Discovery, std::time::Instant>>>,
}

/// Longest accepted client secret file content (trimmed of its trailing newline).
const MAX_SECRET: usize = 255;

impl OidcRuntime {
    /// Validates and reads the secret, derives the public base from the tenant's hosts. Startup only.
    pub fn build(o: &OidcConfig, hosts: &[String]) -> Result<Self> {
        let bad = |m: String| Err(Error::Config(format!("oidc: {m}")));
        let client = crate::auth::oidc::OidcClient::new(&o.issuer, &o.client_id, &o.backchannel_hosts)
            .map_err(|e| Error::Config(format!("oidc: issuer/backchannel_hosts: {e}")))?;
        let raw = std::fs::read_to_string(&o.client_secret_file).map_err(|e| {
            Error::Config(format!(
                "oidc: client_secret_file {}: {e}",
                o.client_secret_file.display()
            ))
        })?;
        let secret = raw.trim_end_matches(['\r', '\n']).to_string();
        if secret.is_empty()
            || secret.len() > MAX_SECRET
            || secret.bytes().any(|b| !(0x21..=0x7e).contains(&b) || b == b':')
        {
            return bad(format!(
                "client_secret_file {}: 1 to {MAX_SECRET} visible ASCII characters, no ':'",
                o.client_secret_file.display()
            ));
        }
        let tls = crate::auth::oidc_net::tls_config(&o.ca_file)
            .map_err(|e| Error::Config(format!("oidc: ca_file {}: {e}", o.ca_file.display())))?;
        let exact = hosts.iter().find(|h| !h.starts_with('*')).ok_or_else(|| {
            Error::Config(
                "oidc: an exact (non-wildcard) host is required: it is the public base URL of redirect_uri".into(),
            )
        })?;
        let host = crate::tenant::normalize_host(exact)
            .ok_or_else(|| Error::Config(format!("oidc: host {exact:?} is not a valid lowercase ASCII name")))?;
        let base = match &o.public_base_url {
            None => format!("https://{host}"),
            Some(raw) => {
                let u = crate::auth::oidc::HttpsUrl::parse(raw)
                    .map_err(|e| Error::Config(format!("oidc: public_base_url {raw:?}: {e}")))?;
                if !u.path_and_query.is_empty() {
                    return Err(Error::Config("oidc: public_base_url: no path or query allowed".into()));
                }
                if !hosts.iter().any(|h| host_entry_matches(h, &u.host)) {
                    return Err(Error::Config(format!(
                        "oidc: public_base_url host {:?} is not one of the tenant's hosts",
                        u.host
                    )));
                }
                if u.port == 443 {
                    format!("https://{}", u.host)
                } else {
                    format!("https://{}:{}", u.host, u.port)
                }
            }
        };
        Ok(Self {
            client,
            secret,
            second_factor: o.second_factor,
            required_amr: o.required_amr.clone(),
            connect_addr: o.connect_addr,
            tls: std::sync::Arc::new(tls),
            base,
            password_login: o.password_login,
            discovery: std::sync::Mutex::new(None),
        })
    }

    /// The `(host, port)` destinations the back channel may resolve (issuer + declared back channel hosts):
    /// the `name2addr` allowlist of the Casper channel (ADR-6).
    pub fn resolvable(&self) -> Vec<(String, u16)> {
        let mut v = vec![(self.client.issuer.host.clone(), self.client.issuer.port)];
        v.extend(self.client.backchannel_hosts().iter().cloned());
        v
    }
}

/// Does a configured host entry (`host` or `*.suffix`) match `host`? Same rule as the router: a wildcard
/// covers exactly one label (as in TLS).
fn host_entry_matches(entry: &str, host: &str) -> bool {
    if let Some(suffix) = entry.strip_prefix("*.") {
        return host.split_once('.').is_some_and(|(_, s)| s == suffix);
    }
    crate::tenant::normalize_host(entry).is_some_and(|n| n == host)
}

/// `off`: not offered (accounts that already have it keep it and may turn it off); `optional`: each user chooses;
/// `required`: set up at the next sign-in, cannot be turned off.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TwoFactor {
    Off,
    #[default]
    Optional,
    Required,
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8080))
}
fn default_state_dir() -> PathBuf {
    PathBuf::from("/var/db/beastbox")
}
fn default_log_level() -> String {
    "info".into()
}
fn default_nc_version() -> String {
    "35.0.0".into()
}
fn default_drop_file() -> u64 {
    1 << 30
}
fn default_trash_days() -> u32 {
    30
}
fn default_share_history_days() -> u32 {
    365
}
fn default_drop_total() -> u64 {
    10 << 30
}
fn default_drop_files() -> u32 {
    500
}
fn default_min_free() -> u64 {
    1 << 30
}
fn default_min_password() -> usize {
    12
}
fn default_amr() -> Vec<String> {
    vec!["mfa".into()]
}
fn default_ca() -> PathBuf {
    PathBuf::from("/etc/ssl/cert.pem")
}
fn default_max_connections() -> usize {
    256
}
fn default_workers() -> usize {
    2
}
fn default_blocking() -> usize {
    4
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        let cfg: Self = toml::from_str(&text).map_err(|e| Error::Config(e.to_string()))?;
        cfg.validate()?;
        // Trusting the provider's own policy, or keeping a local password door, is a decision, not an oversight: say
        // so once at startup.
        for t in &cfg.tenants {
            if let Some(o) = &t.oidc
                && o.password_login
            {
                tracing::warn!(
                    tenant = %t.name,
                    "oidc: password_login = true: the Beastbox password form stays open beside the provider"
                );
            }
            if let Some(o) = &t.oidc
                && o.second_factor == SecondFactor::Provider
                && t.two_factor == TwoFactor::Required
                && o.required_amr.is_empty()
            {
                tracing::warn!(
                    tenant = %t.name,
                    "oidc: second_factor = provider with required_amr = []: the provider's policy is trusted, no second factor is checked"
                );
            }
        }
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        let bad = |m: &str| Err(Error::Config(m.into()));
        if self.listen.ip().is_unspecified() {
            return bad("listen: unspecified address (0.0.0.0 / ::) forbidden");
        }
        if self.trusted_proxies.is_empty() {
            return bad("trusted_proxies empty: no connection would be accepted");
        }
        if !(1..=16).contains(&self.worker_threads) || !(1..=64).contains(&self.blocking_threads) {
            return bad("worker_threads (1-16) or blocking_threads (1-64) out of range");
        }
        if !(1..=10_000).contains(&self.max_connections) {
            return bad("max_connections out of range (1-10000)");
        }
        if self.nc_version().is_none() {
            return bad("nextcloud_version: three numbers expected, e.g. \"35.0.0\"");
        }
        if !self.state_dir.is_absolute() {
            return bad("state_dir must be absolute");
        }
        if !(crate::admin::MIN_PASSWORD..=128).contains(&self.min_password) {
            return bad("min_password out of range (10-128)");
        }
        if self.tenants.is_empty() {
            return bad("no [[tenant]]");
        }
        let mut names = std::collections::HashSet::new();
        // Two tenants sharing both an issuer and a client id would accept each other's tokens (§9).
        let mut oidc_clients = std::collections::HashSet::new();
        for t in &self.tenants {
            let ok = (1..=32).contains(&t.name.len())
                && t.name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if !ok || !names.insert(&t.name) {
                return Err(Error::Config(format!("invalid or duplicate tenant name: {:?}", t.name)));
            }
            if !t.data_root.is_absolute() || t.hosts.is_empty() {
                return Err(Error::Config(format!(
                    "tenant {}: absolute data_root and hosts required",
                    t.name
                )));
            }
            if let Some(raw) = &t.public_base_url {
                base_url(raw, &t.hosts, self.insecure_cookies)
                    .map_err(|m| Error::Config(format!("tenant {}: public_base_url {raw:?}: {m}", t.name)))?;
            }
            if let Some(o) = &t.oidc {
                validate_oidc(&t.name, o)?;
                if !oidc_clients.insert((o.issuer.clone(), o.client_id.clone())) {
                    return bad(&format!(
                        "tenant {}: oidc: this (issuer, client_id) is already used by another tenant",
                        t.name
                    ));
                }
            }
        }
        Ok(())
    }

    /// Parsed `nextcloud_version`: exactly three integers (hence safe to insert into JSON).
    pub fn nc_version(&self) -> Option<[u16; 3]> {
        let mut it = self.nextcloud_version.split('.').map(|n| n.parse::<u16>().ok());
        let v = [it.next()??, it.next()??, it.next()??];
        it.next().is_none().then_some(v)
    }

    pub fn db_path(&self) -> PathBuf {
        self.state_dir.join("app.db")
    }

    /// The public address of `tenant` (`scheme://host[:port]`), for the links the CLI prints: its `public_base_url`,
    /// otherwise its `[tenant.oidc]` one, otherwise `https://` + its first exact host. None of them (wildcard hosts
    /// only): an error that says what to set.
    pub fn public_base(&self, tenant: &str) -> Result<String> {
        let t = self
            .tenants
            .iter()
            .find(|t| t.name == tenant)
            .ok_or_else(|| Error::Config(format!("unknown tenant: {tenant}")))?;
        let given = t
            .public_base_url
            .as_ref()
            .or(t.oidc.as_ref().and_then(|o| o.public_base_url.as_ref()));
        if let Some(raw) = given {
            return base_url(raw, &t.hosts, self.insecure_cookies)
                .map_err(|m| Error::Config(format!("tenant {tenant}: public_base_url {raw:?}: {m}")));
        }
        t.hosts
            .iter()
            .find(|h| !h.starts_with('*'))
            .and_then(|h| crate::tenant::normalize_host(h))
            .map(|h| format!("https://{h}"))
            .ok_or_else(|| {
                Error::Config(format!(
                    "tenant {tenant}: no public address for its links (its hosts are wildcards only): set \
                     public_base_url = \"https://<host>\" in its [[tenant]]"
                ))
            })
    }
}

/// A public base URL, checked: `https://host[:port]` (`http` only when `insecure`, the test bench), the host one of
/// `hosts` (a wildcard covers one label), no user, path, query or fragment; the default port left implicit.
fn base_url(raw: &str, hosts: &[String], insecure: bool) -> std::result::Result<String, &'static str> {
    let (scheme, rest, default) = match (raw.strip_prefix("https://"), raw.strip_prefix("http://")) {
        (Some(r), _) => ("https", r, 443),
        (None, Some(r)) if insecure => ("http", r, 80),
        (None, Some(_)) => return Err("http only on a test bench (insecure_cookies = true)"),
        _ => return Err("https://host[:port] expected"),
    };
    if rest.is_empty() || rest.contains(['/', '@', '?', '#', '\\']) {
        return Err("only scheme://host[:port]: no user, path, query or trailing slash");
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => {
            let ok = !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit());
            match p.parse::<u16>() {
                Ok(n) if ok && n > 0 => (h, n),
                _ => return Err("bad port"),
            }
        }
        None => (rest, default),
    };
    let host = crate::tenant::normalize_host(host).ok_or("bad host")?;
    if !hosts.iter().any(|h| host_entry_matches(h, &host)) {
        return Err("the host is not one of the tenant's hosts");
    }
    Ok(if port == default {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    })
}

/// Hosts the token endpoint may live on, besides the issuer's.
const MAX_BACKCHANNEL_HOSTS: usize = 8;

/// `[tenant.oidc]` checks: the issuer is an `https` URL, the client id fits a header, the paths are absolute, the hosts
/// parse, and no `amr` value is empty.
fn validate_oidc(tenant: &str, o: &OidcConfig) -> Result<()> {
    let bad = |m: &str| Err(Error::Config(format!("tenant {tenant}: {m}")));
    if let Err(e) = crate::auth::oidc::HttpsUrl::parse(&o.issuer) {
        return bad(&format!("oidc.issuer: {e}"));
    }
    let cid_ok = (1..=255).contains(&o.client_id.len()) && o.client_id.bytes().all(|b| (0x21..=0x7e).contains(&b));
    if !cid_ok {
        return bad("oidc.client_id: 1 to 255 visible ASCII characters required");
    }
    if !o.client_secret_file.is_absolute() || !o.ca_file.is_absolute() {
        return bad("oidc.client_secret_file and oidc.ca_file must be absolute");
    }
    if o.required_amr.iter().any(String::is_empty) {
        return bad("oidc.required_amr: empty value");
    }
    if o.backchannel_hosts.len() > MAX_BACKCHANNEL_HOSTS {
        return bad(&format!(
            "oidc.backchannel_hosts: at most {MAX_BACKCHANNEL_HOSTS} hosts"
        ));
    }
    for h in &o.backchannel_hosts {
        if let Err(e) = crate::auth::oidc::parse_host_port(h) {
            return bad(&format!("oidc.backchannel_hosts: {h:?}: {e}"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Config;

    fn parse(s: &str) -> crate::Result<Config> {
        let c: Config = toml::from_str(s).map_err(|e| crate::Error::Config(e.to_string()))?;
        c.validate().map(|()| c)
    }

    const T: &str = "[[tenant]]\nname=\"a\"\nhosts=[\"a.example.org\"]\ndata_root=\"/tmp/a\"\n";

    #[test]
    fn defaults_and_refusals() {
        let c = parse(&format!("trusted_proxies=[\"127.0.0.1\"]\n{T}")).unwrap();
        assert!(c.listen.ip().is_loopback());
        assert!(parse(&format!("listen=\"0.0.0.0:80\"\ntrusted_proxies=[\"127.0.0.1\"]\n{T}")).is_err());
        assert!(parse(&format!("trusted_proxies=[]\n{T}")).is_err());
        assert!(parse(&format!("trusted_proxies=[\"127.0.0.1\"]\nfoo=1\n{T}")).is_err());
        assert!(parse(&format!("trusted_proxies=[\"127.0.0.1\"]\n{T}{T}")).is_err()); // duplicate name
        assert_eq!(c.nc_version(), Some([35, 0, 0]));
        let v = |s: &str| {
            parse(&format!(
                "trusted_proxies=[\"127.0.0.1\"]\nnextcloud_version=\"{s}\"\n{T}"
            ))
        };
        assert_eq!(v("36.1.2").unwrap().nc_version(), Some([36, 1, 2]));
        assert_eq!(c.min_password, 12);
        assert_eq!(c.tenants[0].two_factor, super::TwoFactor::Optional); // default
        let tf = |v: &str| parse(&format!("trusted_proxies=[\"127.0.0.1\"]\n{T}two_factor=\"{v}\"\n"));
        assert_eq!(
            tf("required").unwrap().tenants[0].two_factor,
            super::TwoFactor::Required
        );
        assert_eq!(tf("off").unwrap().tenants[0].two_factor, super::TwoFactor::Off);
        assert!(tf("Required").is_err() && tf("yes").is_err());
        let m = |n: u32| parse(&format!("trusted_proxies=[\"127.0.0.1\"]\nmin_password={n}\n{T}"));
        assert!(m(9).is_err() && m(129).is_err()); // below the floor, absurd
        assert_eq!(m(10).unwrap().min_password, 10);
        assert_eq!(m(128).unwrap().min_password, 128);
        for bad in ["36", "36.1", "36.1.2.3", "36.x.0", "36.1.2\\\"", ""] {
            assert!(v(bad).is_err(), "{bad}");
        }
    }

    /// Every bound of the numeric settings (at, below, above) and every structural refusal.
    #[test]
    fn bounds_and_structure() {
        let p = |extra: &str, tenants: &str| parse(&format!("trusted_proxies=[\"127.0.0.1\"]\n{extra}\n{tenants}"));
        for (k, lo, hi) in [
            ("worker_threads", 1, 16),
            ("blocking_threads", 1, 64),
            ("max_connections", 1, 10_000),
        ] {
            assert!(p(&format!("{k}={}", lo - 1), T).is_err(), "{k} below");
            assert!(p(&format!("{k}={lo}"), T).is_ok(), "{k} at the low bound");
            assert!(p(&format!("{k}={hi}"), T).is_ok(), "{k} at the high bound");
            assert!(p(&format!("{k}={}", hi + 1), T).is_err(), "{k} above");
        }
        assert!(p("state_dir=\"var/db\"", T).is_err()); // relative
        assert!(p("state_dir=\"/var/db/x\"", T).is_ok());
        assert!(p("", "").is_err()); // no tenant
        let tenant = |name: &str, hosts: &str, root: &str| {
            format!("[[tenant]]\nname=\"{name}\"\nhosts={hosts}\ndata_root=\"{root}\"\n")
        };
        assert!(p("", &tenant("a", "[]", "/tmp/a")).is_err()); // no host
        assert!(p("", &tenant("a", "[\"a.example\"]", "tmp/a")).is_err()); // relative root
        for bad in ["", "A", "a_b", "a.b", "a b", &"a".repeat(33)] {
            assert!(p("", &tenant(bad, "[\"a.example\"]", "/tmp/a")).is_err(), "{bad:?}");
        }
        for ok in ["a", "a-1", &"a".repeat(32)] {
            assert!(p("", &tenant(ok, "[\"a.example\"]", "/tmp/a")).is_ok(), "{ok:?}");
        }
        assert_eq!(
            p("", T).unwrap().db_path(),
            std::path::Path::new("/var/db/beastbox/app.db")
        );
    }

    /// Loading a file: missing, unreadable TOML and a refused setting each give a configuration error naming the
    /// problem; a good file loads.
    /// The public address of a tenant, for the links the CLI prints (activation): `public_base_url` when given (https,
    /// or http only on a test bench with `insecure_cookies`; one of the tenant's hosts; no path), otherwise the
    /// `[tenant.oidc]` one, otherwise `https://` + the first exact host; none possible (wildcards only): an error that
    /// says what to add.
    /// `base_url` alone: each refusal says why; a port is plain digits only (`u16::from_str` accepts `+443`), at most
    /// five of them (`000080` parses to 80).
    #[test]
    fn base_url_refusals_say_why() {
        let hosts = ["files.alpha.example".to_string()];
        let b = |raw: &str, insecure: bool| super::base_url(raw, &hosts, insecure);
        assert_eq!(
            b("http://files.alpha.example", false),
            Err("http only on a test bench (insecure_cookies = true)")
        );
        assert_eq!(
            b("ftp://files.alpha.example", true),
            Err("https://host[:port] expected")
        );
        let only = Err("only scheme://host[:port]: no user, path, query or trailing slash");
        assert_eq!(b("https://", false), only);
        assert_eq!(b("https://files.alpha.example/", false), only);
        for bad in ["+443", "000080", "", "8a", "0", "65536"] {
            assert_eq!(
                b(&format!("https://files.alpha.example:{bad}"), false),
                Err("bad port"),
                "{bad}"
            );
        }
        assert_eq!(
            b("https://files.alpha.example:08443", false).as_deref(),
            Ok("https://files.alpha.example:8443")
        );
    }

    #[test]
    fn public_base_of_a_tenant() {
        let c = |top: &str, tenant: &str| {
            parse(&format!(
                "trusted_proxies=[\"127.0.0.1\"]\n{top}\n[[tenant]]\nname=\"alpha\"\nhosts=[\"*.alpha.example\", \"files.alpha.example\"]\ndata_root=\"/tmp/a\"\n{tenant}"
            ))
        };
        assert_eq!(
            c("", "").unwrap().public_base("alpha").unwrap(),
            "https://files.alpha.example"
        );
        let given = c("", "public_base_url=\"https://www.alpha.example:8443\"").unwrap();
        assert_eq!(given.public_base("alpha").unwrap(), "https://www.alpha.example:8443");
        let std_port = c("", "public_base_url=\"https://files.alpha.example:443\"").unwrap();
        assert_eq!(std_port.public_base("alpha").unwrap(), "https://files.alpha.example");
        // http: only on a test bench.
        assert!(c("", "public_base_url=\"http://files.alpha.example:8480\"").is_err());
        let bench = c(
            "insecure_cookies = true",
            "public_base_url=\"http://files.alpha.example:8480\"",
        )
        .unwrap();
        assert_eq!(bench.public_base("alpha").unwrap(), "http://files.alpha.example:8480");
        for bad in [
            "https://evil.example",
            "https://files.alpha.example/path",
            "https://files.alpha.example/",
            "ftp://files.alpha.example",
            "https://files.alpha.example:0",
            "https://files.alpha.example:99999",
            "https://user@files.alpha.example",
            "files.alpha.example",
        ] {
            assert!(c("", &format!("public_base_url=\"{bad}\"")).is_err(), "{bad}");
        }
        // Wildcards only, nothing given: an error that names the setting.
        let wild = parse(
            "trusted_proxies=[\"127.0.0.1\"]\n[[tenant]]\nname=\"alpha\"\nhosts=[\"*.alpha.example\"]\ndata_root=\"/tmp/a\"\n",
        )
        .unwrap();
        assert!(
            wild.public_base("alpha")
                .unwrap_err()
                .to_string()
                .contains("public_base_url")
        );
        assert!(c("", "").unwrap().public_base("nope").is_err());
        // The default port of http is left implicit; without its own setting, the [tenant.oidc] one is used.
        let bench80 = c(
            "insecure_cookies = true",
            "public_base_url=\"http://files.alpha.example:80\"",
        )
        .unwrap();
        assert_eq!(bench80.public_base("alpha").unwrap(), "http://files.alpha.example");
        let from_oidc = c(
            "",
            "[tenant.oidc]\nissuer=\"https://auth.example\"\nclient_id=\"c\"\nclient_secret_file=\"/etc/s\"\n\
             public_base_url=\"https://www.alpha.example:8443\"",
        )
        .unwrap();
        assert_eq!(
            from_oidc.public_base("alpha").unwrap(),
            "https://www.alpha.example:8443"
        );
    }

    #[test]
    fn load_from_file() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("b.toml");
        assert!(matches!(Config::load(&f), Err(crate::Error::Config(m)) if m.contains("b.toml")));
        std::fs::write(&f, "trusted_proxies = [").unwrap();
        assert!(matches!(Config::load(&f), Err(crate::Error::Config(_))));
        std::fs::write(&f, format!("trusted_proxies=[]\n{T}")).unwrap();
        assert!(matches!(Config::load(&f), Err(crate::Error::Config(m)) if m.contains("trusted_proxies")));
        std::fs::write(&f, format!("trusted_proxies=[\"127.0.0.1\"]\n{T}")).unwrap();
        assert_eq!(Config::load(&f).unwrap().tenants.len(), 1);
        // Trusting the provider's policy (no required second factor): loaded, with a warning at startup.
        std::fs::write(
            &f,
            "trusted_proxies=[\"127.0.0.1\"]\n[[tenant]]\nname=\"alpha\"\nhosts=[\"files.alpha.example\"]\ndata_root=\"/tmp/a\"\ntwo_factor=\"required\"\n[tenant.oidc]\nissuer=\"https://auth.example\"\nclient_id=\"c\"\nclient_secret_file=\"/etc/s\"\nsecond_factor=\"provider\"\nrequired_amr=[]\n",
        )
        .unwrap();
        let c = Config::load(&f).unwrap();
        assert_eq!(c.tenants[0].two_factor, super::TwoFactor::Required);
        assert!(c.tenants[0].oidc.as_ref().unwrap().required_amr.is_empty());
    }

    /// `[tenant.oidc]`: every key taken, its default, an unknown key refused.
    #[test]
    fn oidc_defaults_and_keys() {
        let base = |extra: &str| {
            parse(&format!(
                "trusted_proxies=[\"127.0.0.1\"]\n[[tenant]]\nname=\"alpha\"\nhosts=[\"files.alpha.example\"]\ndata_root=\"/tmp/a\"\n[tenant.oidc]\nissuer=\"https://auth.example\"\nclient_id=\"beastbox-alpha\"\nclient_secret_file=\"/etc/beastbox-alpha-oidc.secret\"\n{extra}"
            ))
        };
        let o = base("").unwrap().tenants[0].oidc.clone().unwrap();
        assert_eq!(o.second_factor, super::SecondFactor::Beastbox);
        assert_eq!(o.required_amr, ["mfa".to_string()]);
        assert_eq!(o.ca_file, std::path::Path::new("/etc/ssl/cert.pem"));
        assert!(o.connect_addr.is_none() && o.backchannel_hosts.is_empty());
        // The password form is off by default on a tenant with a provider.
        assert!(!o.password_login);
        let o = base("password_login=true\n").unwrap().tenants[0].oidc.clone().unwrap();
        assert!(o.password_login);
        let o = base("second_factor=\"provider\"\nrequired_amr=[\"hwk\", \"mfa\"]\nconnect_addr=\"192.0.2.10:443\"\nbackchannel_hosts=[\"token.auth.example\"]\nca_file=\"/etc/ssl/private-ca.pem\"\n")
            .unwrap()
            .tenants[0]
            .oidc
            .clone()
            .unwrap();
        assert_eq!(o.second_factor, super::SecondFactor::Provider);
        assert_eq!(o.required_amr, ["hwk".to_string(), "mfa".to_string()]);
        assert_eq!(o.connect_addr, Some("192.0.2.10:443".parse().unwrap()));
        assert_eq!(o.backchannel_hosts, ["token.auth.example"]);
        assert_eq!(o.ca_file, std::path::Path::new("/etc/ssl/private-ca.pem"));
        // provider + required + no amr: accepted (the provider's policy is trusted, warned at startup).
        assert!(base("second_factor=\"provider\"\nrequired_amr=[]\n").is_ok());
        assert!(base("unknown=\"x\"\n").is_err());
        assert!(base("second_factor=\"Provider\"\n").is_err());
        assert!(base("second_factor=\"yes\"\n").is_err());
        assert!(
            parse(&format!("trusted_proxies=[\"127.0.0.1\"]\n{T}")).unwrap().tenants[0]
                .oidc
                .is_none()
        );
        // Required keys: a missing one is refused by serde.
        let full = "trusted_proxies=[\"127.0.0.1\"]\n[[tenant]]\nname=\"alpha\"\nhosts=[\"files.alpha.example\"]\ndata_root=\"/tmp/a\"\n[tenant.oidc]\nissuer=\"https://auth.example\"\nclient_id=\"beastbox-alpha\"\nclient_secret_file=\"/etc/s\"\n";
        for key in ["issuer", "client_id", "client_secret_file"] {
            let text: Vec<&str> = full.lines().filter(|l| !l.starts_with(key)).collect();
            assert!(parse(&text.join("\n")).is_err(), "{key} missing");
        }
    }

    /// The issuer goes through the strict `https` grammar; the client id, the paths and the back channel hosts too.
    #[test]
    fn oidc_issuer_client_and_hosts() {
        let cfg = |issuer: &str, cid: &str, extra: &str| {
            parse(&format!(
                "trusted_proxies=[\"127.0.0.1\"]\n[[tenant]]\nname=\"alpha\"\nhosts=[\"files.alpha.example\"]\ndata_root=\"/tmp/a\"\n[tenant.oidc]\nissuer=\"{issuer}\"\nclient_id=\"{cid}\"\nclient_secret_file=\"/etc/s\"\n{extra}"
            ))
        };
        // Accepted issuers, kept byte for byte (trailing slash and path included).
        for issuer in [
            "https://auth.example",
            "https://auth.example/",
            "https://auth.example:8443",
            "https://auth.example/application/o/alpha/",
        ] {
            let c = cfg(issuer, "beastbox-alpha", "").unwrap();
            assert_eq!(c.tenants[0].oidc.as_ref().unwrap().issuer, issuer);
        }
        // A URL of 2,048 bytes is accepted, 2,049 refused.
        let long = |n: usize| {
            let mut s = String::from("https://auth.example/");
            s.push_str(&"a".repeat(n - s.len()));
            s
        };
        assert!(cfg(&long(2_048), "c", "").is_ok());
        assert!(cfg(&long(2_049), "c", "").is_err());
        for issuer in [
            "http://auth.example",
            "https://user@auth.example",
            "https://auth.example/#top",
            "https://AUTH.example",
            "https://auth.example:0",
            "https://auth.example:65536",
            "https://auth.example\\x",
            "",
        ] {
            assert!(cfg(issuer, "c", "").is_err(), "{issuer:?}");
        }
        // client_id: 1 to 255 visible ASCII.
        assert!(cfg("https://auth.example", "", "").is_err());
        assert!(cfg("https://auth.example", &"c".repeat(255), "").is_ok());
        assert!(cfg("https://auth.example", &"c".repeat(256), "").is_err());
        for cid in ["a b", "a\tb", "a\u{7}", "é"] {
            assert!(cfg("https://auth.example", cid, "").is_err(), "{cid:?}");
        }
        // Absolute paths.
        let absolute = |extra: &str| cfg("https://auth.example", "c", extra).is_ok();
        assert!(absolute("ca_file=\"/etc/ssl/ca.pem\"\n"));
        assert!(!absolute("ca_file=\"ssl/ca.pem\"\n"));
        assert!(!absolute("client_secret_file=\"secret\"\n"));
        // required_amr: no empty value.
        assert!(!absolute("required_amr=[\"mfa\", \"\"]\n"));
        assert!(absolute("required_amr=[]\n"));
        // backchannel_hosts: 8 hosts accepted, 9 refused; `host` or `host:port` only.
        let hosts = |n: usize| {
            let list: Vec<String> = (0..n).map(|i| format!("\"t{i}.auth.example\"")).collect();
            format!("backchannel_hosts=[{}]\n", list.join(", "))
        };
        assert!(absolute(&hosts(8)));
        assert!(!absolute(&hosts(9)));
        assert!(absolute(
            "backchannel_hosts=[\"token.auth.example\", \"auth.example:8443\"]\n"
        ));
        for bad in [
            "https://token.auth.example",
            "Auth.example",
            "token.auth.example/x",
            "token.auth.example:0",
        ] {
            assert!(!absolute(&format!("backchannel_hosts=[\"{bad}\"]\n")), "{bad:?}");
        }
    }

    /// `OidcRuntime::build`: the secret is read once at startup (bounded, visible ASCII, no ':'), the public
    /// base URL comes from the first exact host (never a wildcard, never the request's `Host` header), and the
    /// Casper allowlist lists the issuer and the back channel hosts.
    #[test]
    fn oidc_runtime_build() {
        use super::{OidcRuntime, SecondFactor};
        let d = tempfile::tempdir().unwrap();
        let secret = d.path().join("secret");
        let mk = |extra: &str| {
            format!(
                "trusted_proxies=[\"127.0.0.1\"]\n[[tenant]]\nname=\"alpha\"\nhosts=[\"files.alpha.example\",\"*.alpha.example\"]\ndata_root=\"/tmp/a\"\n[tenant.oidc]\nissuer=\"https://auth.example\"\nclient_id=\"beastbox-alpha\"\nclient_secret_file=\"{}\"\n{extra}",
                secret.display()
            )
        };
        // Missing secret file: refused.
        assert!(parse(&mk("")).is_ok()); // config alone is fine
        let c = parse(&mk("")).unwrap();
        assert!(OidcRuntime::build(c.tenants[0].oidc.as_ref().unwrap(), &c.tenants[0].hosts).is_err());
        // Secret with a ':' or a newline inside: refused (Basic header ambiguity / header injection).
        std::fs::write(&secret, "good-secret\n").unwrap();
        let c = parse(&mk(
            "backchannel_hosts=[\"token.auth.example\", \"auth.example:8443\"]\n",
        ))
        .unwrap();
        let o = c.tenants[0].oidc.as_ref().unwrap();
        let r = OidcRuntime::build(o, &c.tenants[0].hosts).unwrap();
        assert_eq!(r.secret, "good-secret");
        assert_eq!(r.base, "https://files.alpha.example");
        assert_eq!(r.second_factor, SecondFactor::Beastbox);
        assert_eq!(r.required_amr, ["mfa".to_string()]);
        assert_eq!(
            r.resolvable(),
            vec![
                ("auth.example".to_string(), 443),
                ("token.auth.example".to_string(), 443),
                ("auth.example".to_string(), 8443)
            ]
        );
        // 255 characters is the bound: accepted; 256 refused (and the other refusals).
        std::fs::write(&secret, "s".repeat(255)).unwrap();
        assert!(
            OidcRuntime::build(o, &c.tenants[0].hosts).is_ok(),
            "255 characters refused"
        );
        for bad in ["a:b", "a\nb", "", "  ", &"s".repeat(256)] {
            std::fs::write(&secret, bad).unwrap();
            assert!(OidcRuntime::build(o, &c.tenants[0].hosts).is_err(), "{bad:?}");
        }
        std::fs::write(&secret, "good-secret\n").unwrap();
        // Missing or unusable CA bundle: refused at startup, not at the first sign-in (after `cap_enter()` an
        // absolute path can no longer be opened).
        let c = parse(&mk("ca_file=\"/nonexistent/ca.pem\"\n")).unwrap();
        let e = OidcRuntime::build(c.tenants[0].oidc.as_ref().unwrap(), &c.tenants[0].hosts).unwrap_err();
        assert!(e.to_string().contains("ca_file"), "{e}");
        let empty = d.path().join("empty.pem");
        std::fs::write(&empty, b"").unwrap();
        let c = parse(&mk(&format!("ca_file=\"{}\"\n", empty.display()))).unwrap();
        let e = OidcRuntime::build(c.tenants[0].oidc.as_ref().unwrap(), &c.tenants[0].hosts).unwrap_err();
        assert!(e.to_string().contains("ca_file"), "{e}");
        // Only a wildcard host: no public base URL possible → refused.
        let wildcard_only: Vec<String> = vec!["*.alpha.example".into()];
        assert!(OidcRuntime::build(o, &wildcard_only).is_err());
        // public_base_url: explicit port on a tenant host, default port kept implicit, wildcard match.
        let c = parse(&mk("public_base_url=\"https://files.alpha.example:8443\"\n")).unwrap();
        let r = OidcRuntime::build(c.tenants[0].oidc.as_ref().unwrap(), &c.tenants[0].hosts).unwrap();
        assert_eq!(r.base, "https://files.alpha.example:8443");
        let c = parse(&mk("public_base_url=\"https://www.alpha.example\"\n")).unwrap();
        let r = OidcRuntime::build(c.tenants[0].oidc.as_ref().unwrap(), &c.tenants[0].hosts).unwrap();
        assert_eq!(r.base, "https://www.alpha.example");
        // Refused: not https, host outside the tenant's hosts, a path, a bad port.
        for bad in [
            "http://files.alpha.example",
            "https://evil.example",
            "https://files.alpha.example/path",
            "https://files.alpha.example:8443/",
            "https://files.alpha.example:+8443",
        ] {
            let c = parse(&mk(&format!("public_base_url=\"{bad}\"\n"))).unwrap();
            assert!(
                OidcRuntime::build(c.tenants[0].oidc.as_ref().unwrap(), &c.tenants[0].hosts).is_err(),
                "{bad}"
            );
        }
    }

    /// The test-bench flags are off by default and parse when set explicitly.
    #[test]
    fn insecure_bench_flags() {
        let base =
            "trusted_proxies=[\"127.0.0.1\"]\n[[tenant]]\nname=\"a\"\nhosts=[\"a.example\"]\ndata_root=\"/tmp/a\"\n";
        let c = parse(base).unwrap();
        assert!(!c.insecure_cookies);
        let c = parse(&format!("insecure_cookies=true\n{base}")).unwrap();
        assert!(c.insecure_cookies);
    }

    /// Two tenants may share an issuer or a client id, never both: they would accept each other's tokens (§9).
    #[test]
    fn oidc_clients_unique_across_tenants() {
        let two = |(i1, c1): (&str, &str), (i2, c2): (&str, &str)| {
            let t = |name: &str, issuer: &str, cid: &str| {
                format!(
                    "[[tenant]]\nname=\"{name}\"\nhosts=[\"{name}.example\"]\ndata_root=\"/tmp/{name}\"\n[tenant.oidc]\nissuer=\"{issuer}\"\nclient_id=\"{cid}\"\nclient_secret_file=\"/etc/s\"\n"
                )
            };
            parse(&format!(
                "trusted_proxies=[\"127.0.0.1\"]\n{}{}",
                t("alpha", i1, c1),
                t("beta", i2, c2)
            ))
        };
        assert!(two(("https://auth.example", "a"), ("https://auth.example", "b")).is_ok());
        assert!(two(("https://auth.example", "a"), ("https://other.example", "a")).is_ok());
        let e = two(("https://auth.example", "a"), ("https://auth.example", "a"));
        assert!(matches!(e, Err(crate::Error::Config(m)) if m.contains("already used")));
    }
}
