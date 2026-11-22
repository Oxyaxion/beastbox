//! Tenant resolution (§4, §4.1). `TenantCtx` can only be constructed in this module, after resolving
//! and validating the host name: every function that touches files or the database requires it.

use crate::config::{OidcRuntime, TenantConfig};
use crate::fs::Root;
use crate::{Error, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A tenant to register: name, host names, data root, key, link key, OIDC client (runtime).
pub(crate) type Part = (String, Vec<String>, Root, [u8; 32], [u8; 32], Option<OidcRuntime>);

#[derive(Debug)]
pub struct Tenant {
    name: String,
    data_root: Root,
    /// The tenant's HMAC key (§2, §5): digests of app tokens, sessions and links.
    key: [u8; 32],
    /// Key the public link tokens are derived from (§8): renewing it ends every link without logging anyone out.
    link_key: [u8; 32],
    /// Single sign-on client, when `[tenant.oidc]` is configured (None: password only).
    oidc: Option<OidcRuntime>,
    flows: crate::nc::Flows,
    failures: crate::auth::Failures,
    /// Single sign-on flows already used (a flow signs in once).
    oidc_used: crate::auth::oidc::UsedFlows,
    journal: crate::fs::Journal,
    index: crate::index::Indexes,
}

/// Tenant context. Private field: impossible to forge outside `tenant/`.
#[derive(Clone, Debug)]
pub struct TenantCtx(Arc<Tenant>);

impl TenantCtx {
    pub fn name(&self) -> &str {
        &self.0.name
    }
    pub fn data_root(&self) -> &Root {
        &self.0.data_root
    }
    /// HMAC-SHA-256 digest of a secret, bound to the tenant (§4.1): tenant key, and tenant name in the data.
    pub fn mac(&self, secret: &[u8]) -> [u8; 32] {
        use hmac::{KeyInit, Mac};
        let Ok(mut m) = hmac::Hmac::<sha2::Sha256>::new_from_slice(&self.0.key) else {
            return [0; 32]; // unreachable: HMAC accepts any key length
        };
        m.update(self.0.name.as_bytes());
        m.update(&[0]);
        m.update(secret);
        m.finalize().into_bytes().into()
    }
    /// Same as `mac`, with the link key: public link tokens and their password cookies.
    pub fn link_mac(&self, data: &[u8]) -> [u8; 32] {
        use hmac::{KeyInit, Mac};
        let Ok(mut m) = hmac::Hmac::<sha2::Sha256>::new_from_slice(&self.0.link_key) else {
            return [0; 32]; // unreachable: HMAC accepts any key length
        };
        m.update(self.0.name.as_bytes());
        m.update(&[0]);
        m.update(data);
        m.finalize().into_bytes().into()
    }
    pub(crate) fn flows(&self) -> &crate::nc::Flows {
        &self.0.flows
    }
    pub(crate) fn failures(&self) -> &crate::auth::Failures {
        &self.0.failures
    }
    pub(crate) fn oidc_used(&self) -> &crate::auth::oidc::UsedFlows {
        &self.0.oidc_used
    }
    /// ETag intent journal (§6). Closed until `serve` has opened it: writes refused.
    pub fn journal(&self) -> &crate::fs::Journal {
        &self.0.journal
    }
    pub fn index(&self) -> &crate::index::Indexes {
        &self.0.index
    }
    /// The tenant's OIDC client (runtime config), when `[tenant.oidc]` is set.
    pub fn oidc(&self) -> Option<&OidcRuntime> {
        self.0.oidc.as_ref()
    }

    /// May the web sign-in use a Beastbox password? No on a tenant that delegates its sign-in to a provider,
    /// unless `password_login = true` keeps that door open.
    pub fn password_login_allowed(&self) -> bool {
        self.oidc().is_none_or(|o| o.password_login)
    }

    /// Does the provider hold the second factor of every web session? Only with `second_factor = "provider"` and
    /// no password door: then every session comes from the provider (its `amr` checked), and a tenant's
    /// `two_factor = required` must not ask for a Beastbox TOTP on top.
    pub fn provider_second_factor(&self) -> bool {
        self.oidc()
            .is_some_and(|o| o.second_factor == crate::config::SecondFactor::Provider && !o.password_login)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum HostError {
    /// Header missing, multiple, contradictory or malformed → 400.
    Invalid,
    /// Valid name but served by no tenant → 421, revealing nothing.
    Unknown,
}

/// Tenant registry: the only source of `TenantCtx`.
#[derive(Debug)]
pub struct Registry {
    exact: HashMap<String, TenantCtx>,
    /// Key = suffix after `*.`; a wildcard covers exactly one label (as in TLS).
    wildcard: HashMap<String, TenantCtx>,
    by_name: Vec<TenantCtx>,
}

impl Registry {
    /// Opens the roots, checks the storage (§2), that they are disjoint and that host names are unambiguous.
    /// HMAC keys are read (or created) in `<state_dir>/keys/<tenant>.key`, link keys in `<tenant>.links.key`.
    pub fn build(cfgs: &[TenantConfig], state_dir: &Path) -> Result<Self> {
        let keys = state_dir.join("keys");
        std::fs::create_dir_all(&keys).map_err(|e| Error::Config(format!("{}: {e}", keys.display())))?;
        let mut parts = Vec::new();
        let mut seen: Vec<(PathBuf, u64, &str)> = Vec::new();
        for c in cfgs {
            let ctx = |e: std::io::Error| {
                Error::Config(format!("tenant {} : data_root {} : {e}", c.name, c.data_root.display()))
            };
            let root = Root::open_dir(&c.data_root).map_err(ctx)?;
            root.check_storage()
                .map_err(|e| Error::Config(format!("tenant {} : {e}", c.name)))?;
            let canon = c.data_root.canonicalize().map_err(ctx)?;
            let dev = root.dev().map_err(ctx)?;
            for (p, d, other) in &seen {
                if canon.starts_with(p) || p.starts_with(&canon) || *d == dev {
                    return Err(Error::Config(format!(
                        "tenants {other} and {}: nested roots or on the same dataset",
                        c.name
                    )));
                }
            }
            seen.push((canon, dev, &c.name));
            let kp = keys.join(format!("{}.key", c.name));
            let key =
                crate::fs::load_or_create_key(&kp).map_err(|e| Error::Config(format!("{}: {e}", kp.display())))?;
            let lp = keys.join(format!("{}.links.key", c.name));
            let link_key =
                crate::fs::load_or_create_key(&lp).map_err(|e| Error::Config(format!("{}: {e}", lp.display())))?;
            // The OIDC secret is read now, before Capsicum: no path access is possible afterwards.
            let oidc = match &c.oidc {
                Some(o) => Some(OidcRuntime::build(o, &c.hosts)?),
                None => None,
            };
            parts.push((c.name.clone(), c.hosts.clone(), root, key, link_key, oidc));
        }
        Self::from_parts(parts)
    }

    pub(crate) fn from_parts(parts: Vec<Part>) -> Result<Self> {
        let mut reg = Self {
            exact: HashMap::new(),
            wildcard: HashMap::new(),
            by_name: Vec::new(),
        };
        for (name, hosts, data_root, key, link_key, oidc) in parts {
            let ctx = TenantCtx(Arc::new(Tenant {
                name,
                data_root,
                key,
                link_key,
                oidc,
                flows: Default::default(),
                failures: Default::default(),
                oidc_used: Default::default(),
                journal: Default::default(),
                index: Default::default(),
            }));
            for h in hosts {
                let (map, key) = match h.strip_prefix("*.") {
                    Some(suffix) => (&mut reg.wildcard, suffix),
                    None => (&mut reg.exact, h.as_str()),
                };
                let norm = normalize_host(key).filter(|n| n == key).ok_or_else(|| {
                    Error::Config(format!(
                        "host name {h:?}: lowercase ASCII (punycode) without port or trailing dot"
                    ))
                })?;
                // shortcut: "registrable domain" approximated by >= 2 labels (refuses *.fr, accepts *.co.uk);
                // switch to the Public Suffix List if a tenant needs it.
                if h.starts_with("*.") && !norm.contains('.') {
                    return Err(Error::Config(format!("motif joker trop large : {h}")));
                }
                if map.insert(norm, ctx.clone()).is_some() {
                    return Err(Error::Config(format!("host name claimed twice: {h}")));
                }
            }
            reg.by_name.push(ctx);
        }
        // An exact name covered by ANOTHER tenant's wildcard is ambiguous: refused (one host = one tenant).
        for (host, t) in &reg.exact {
            if let Some(w) = host.split_once('.').and_then(|(_, s)| reg.wildcard.get(s))
                && !Arc::ptr_eq(&w.0, &t.0)
            {
                return Err(Error::Config(format!(
                    "{host}: covered by tenants {} and {}",
                    t.name(),
                    w.name()
                )));
            }
        }
        Ok(reg)
    }

    /// Resolves a raw host name (already extracted from `Host` or `X-Forwarded-Host`). Exact match first.
    pub fn resolve(&self, raw: &str) -> std::result::Result<TenantCtx, HostError> {
        let h = normalize_host(raw).ok_or(HostError::Invalid)?;
        if let Some(t) = self.exact.get(&h) {
            return Ok(t.clone());
        }
        h.split_once('.')
            .and_then(|(_, s)| self.wildcard.get(s))
            .cloned()
            .ok_or(HostError::Unknown)
    }

    /// For the local CLI only (the name comes from the administrator, not from a request).
    pub fn by_name(&self, name: &str) -> Option<TenantCtx> {
        self.by_name.iter().find(|t| t.name() == name).cloned()
    }

    pub fn all(&self) -> &[TenantCtx] {
        &self.by_name
    }
}

/// Normalization (§4.1): lowercase, no port or trailing dot; refuses userinfo, characters outside
/// `[a-z0-9.-]`, empty or too-long labels, IPv6 literals. IDN names must arrive as punycode
/// (A-labels): that is what HTTP clients send, no IDNA decoding is done here.
pub fn normalize_host(raw: &str) -> Option<String> {
    let host = match raw.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) && port.len() <= 5 => h,
        Some(_) => return None,
        None => raw,
    };
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    let ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && host
            .split('.')
            .all(|l| (1..=63).contains(&l.len()) && !l.starts_with('-') && !l.ends_with('-'));
    ok.then_some(host)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Two-tenant bench (§10): roots in distinct temporary folders.
    pub(crate) fn two_tenants() -> (Registry, tempfile::TempDir, tempfile::TempDir) {
        two_tenants_with(None, None)
    }

    /// Same, with an OIDC client on alpha and/or beta (web OIDC tests): the runtime config of each.
    pub(crate) fn two_tenants_with(
        alpha_oidc: Option<OidcRuntime>,
        beta_oidc: Option<OidcRuntime>,
    ) -> (Registry, tempfile::TempDir, tempfile::TempDir) {
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let reg = Registry::from_parts(vec![
            (
                "alpha".into(),
                vec!["files.alpha.example".into(), "*.alpha.example".into()],
                Root::open_dir(a.path()).unwrap(),
                [1; 32],
                [11; 32],
                alpha_oidc,
            ),
            (
                "beta".into(),
                vec!["*.beta.example".into()],
                Root::open_dir(b.path()).unwrap(),
                [2; 32],
                [12; 32],
                beta_oidc,
            ),
        ])
        .unwrap();
        (reg, a, b)
    }

    fn try_reg(hosts_a: &[&str], hosts_b: &[&str]) -> Result<Registry> {
        let d = tempfile::tempdir().unwrap();
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect();
        Registry::from_parts(vec![
            (
                "a".into(),
                s(hosts_a),
                Root::open_dir(d.path()).unwrap(),
                [1; 32],
                [11; 32],
                None,
            ),
            (
                "b".into(),
                s(hosts_b),
                Root::open_dir(d.path()).unwrap(),
                [2; 32],
                [12; 32],
                None,
            ),
        ])
    }

    #[test]
    fn resolution() {
        let (r, _a, _b) = two_tenants();
        assert_eq!(r.resolve("files.alpha.example").unwrap().name(), "alpha");
        assert_eq!(r.resolve("FILES.Alpha.EXAMPLE.:443").unwrap().name(), "alpha");
        assert_eq!(r.resolve("x.alpha.example").unwrap().name(), "alpha");
        assert_eq!(r.resolve("cloud.beta.example").unwrap().name(), "beta");
        assert_eq!(r.resolve("alpha.example").unwrap_err(), HostError::Unknown);
        assert_eq!(r.resolve("a.b.alpha.example").unwrap_err(), HostError::Unknown);
        assert_eq!(r.resolve("evil.fr").unwrap_err(), HostError::Unknown);
        for bad in [
            "",
            "user@files.alpha.example",
            "files.alpha.example:",
            "files.alpha.example:x",
            "[::1]:80",
            "a..fr",
            "fïles.alpha.example",
            "files.alpha.example, x.beta.example",
            "-a.alpha.example",
            "a b",
            "files.alpha.example:123456",
        ] {
            assert_eq!(r.resolve(bad).unwrap_err(), HostError::Invalid, "{bad:?}");
        }
    }

    #[test]
    fn config_refusals() {
        assert!(try_reg(&["x.org"], &["x.org"]).is_err()); // same name, two tenants
        assert!(try_reg(&["*.x.org"], &["*.x.org"]).is_err());
        assert!(try_reg(&["a.x.org"], &["*.x.org"]).is_err()); // exact covered by another's wildcard
        assert!(try_reg(&["*.fr"], &["b.org"]).is_err()); // too broad
        assert!(try_reg(&["*"], &["b.org"]).is_err());
        assert!(try_reg(&["A.org"], &["b.org"]).is_err()); // not normalized
        assert!(try_reg(&["a.org:80"], &["b.org"]).is_err());
        assert!(try_reg(&["a.x.org", "*.x.org"], &["b.org"]).is_ok()); // same tenant: no ambiguity
    }

    #[test]
    fn roots_must_be_distinct_datasets() {
        // Two roots on the same filesystem (same st_dev): startup refused.
        let (a, b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let state = tempfile::tempdir().unwrap();
        let t = |n: &str, h: &str, p: &std::path::Path| TenantConfig {
            name: n.into(),
            hosts: vec![h.into()],
            data_root: p.into(),
            two_factor: Default::default(),
            public_base_url: None,
            oidc: None,
        };
        let err = Registry::build(&[t("a", "a.org", a.path()), t("b", "b.org", b.path())], state.path()).unwrap_err();
        assert!(err.to_string().contains("same dataset"));
        let nested = a.path().join("n");
        std::fs::create_dir(&nested).unwrap();
        assert!(Registry::build(&[t("a", "a.org", a.path()), t("b", "b.org", &nested)], state.path()).is_err());
        // A data root that does not exist: startup refused, and the message names the tenant and the folder.
        let gone = a.path().join("absent");
        let err = Registry::build(&[t("a", "a.org", &gone)], state.path())
            .unwrap_err()
            .to_string();
        assert!(err.contains("tenant a") && err.contains("absent"), "{err}");
        assert!(Registry::build(&[t("a", "a.org", a.path())], state.path()).is_ok());
    }
}
