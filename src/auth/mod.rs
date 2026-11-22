//! Authentication (§2): app passwords (the only ones accepted by WebDAV and OCS, HMAC digest,
//! checked in microseconds) and human passwords (argon2id, Login Flow only, bounded concurrency).
//! `UserCtx` can only be constructed here, after a successful authentication in a tenant.

pub mod oidc;
pub mod oidc_net;
pub mod totp;

use crate::db::Db;
use crate::fs::{Root, SafePath};
use crate::tenant::TenantCtx;
use crate::{Error, Result};
use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash};
use base64ct::Encoding;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Authentication failures tolerated per IP and per window (§2, §4); beyond that: 429 until the end of the window.
const IP_MAX_FAILS: u32 = 10;
const IP_WINDOW: Duration = Duration::from_secs(5 * 60);
/// Entries tracked per table and tenant: bounded (§0.4). A table of addresses full of live ones lets an address it does
/// not know through (refusing it would close the door to everyone, M1): what that address may try stays bounded by
/// the per-account, per-link and per-code limits, which only real names can fill.
const IP_MAX_ENTRIES: usize = 4096;

/// Wrong passwords tolerated per existing account and per window, all addresses combined (M2: a guessed account is
/// locked, never the whole tenant), except on a device the account already signed in from (`known_device`).
const ACCOUNT_MAX_FAILS: u32 = 10;
const ACCOUNT_WINDOW: Duration = Duration::from_secs(15 * 60);

/// The known-device mark of an account, set as a cookie after a right password: a device holding it is not stopped by
/// the account's lock (the owner keeps a door an attacker guessing from elsewhere cannot use). It opens nothing by
/// itself: the password is still checked. Bound to the tenant key and the account.
pub fn known_device(t: &TenantCtx, user: &str) -> String {
    hex(&t.mac(format!("known-device\0{user}").as_bytes()))
}

pub fn known_device_ok(t: &TenantCtx, user: &str, value: &str) -> bool {
    constant_time_eq(known_device(t, user).as_bytes(), value.as_bytes())
}

/// Wrong second steps tolerated per account and per window, all IPs combined: with ±1 step, 5 tries leave a chance of
/// 1.5e-5 per window to an attacker who has the password.
const USER_MAX_CODE_FAILS: u32 = 5;
const USER_WINDOW: Duration = Duration::from_secs(15 * 60);

/// The key an address is counted under: an IPv4 address itself (also when written IPv4-mapped, `::ffff:a.b.c.d`), an
/// IPv6 address by its /64 (what one subscriber, one machine or one attacker usually holds: counting each address
/// alone would give them 2^64 tries).
pub(crate) fn ip_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

/// Failures counted per name (an account, a link) in their own table, never mixed with addresses: bounded like
/// `by_ip`; a poisoned lock or a table full of live entries answers blocked (fail closed).
#[derive(Debug, Default)]
struct Named(Mutex<HashMap<String, (u32, Instant)>>);

impl Named {
    fn blocked_at(&self, name: &str, now: Instant, max: u32, window: Duration) -> bool {
        let Ok(mut m) = self.0.lock() else { return true };
        match m.get(name) {
            Some(&(n, t)) if now.duration_since(t) < window => n >= max,
            Some(_) => {
                m.remove(name);
                false
            }
            None => {
                if m.len() >= IP_MAX_ENTRIES {
                    m.retain(|_, (_, t)| now.duration_since(*t) < window);
                }
                m.len() >= IP_MAX_ENTRIES
            }
        }
    }

    /// Counts one failure; the count reached (0 when not recorded: table full).
    fn record_at(&self, name: &str, now: Instant, window: Duration) -> u32 {
        let Ok(mut m) = self.0.lock() else { return 0 };
        if m.len() >= IP_MAX_ENTRIES && !m.contains_key(name) {
            m.retain(|_, (_, t)| now.duration_since(*t) < window);
            if m.len() >= IP_MAX_ENTRIES {
                tracing::warn!("failure table full");
                return 0;
            }
        }
        let e = m.entry(name.to_owned()).or_insert((0, now));
        if now.duration_since(e.1) >= window {
            *e = (0, now);
        }
        e.0 += 1;
        e.0
    }
}

/// A tenant's failure counters (per address: `ip_key`). In memory: a restart resets them.
#[derive(Debug, Default)]
pub struct Failures {
    by_ip: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    /// Wrong passwords per existing account.
    by_account: Named,
    /// Wrong second steps per account.
    code_by_user: Named,
    /// Wrong passwords per share link (its identifier), with the per-IP limits.
    by_link: Named,
}

impl Failures {
    /// Has the IP exhausted its attempts? Poisoned lock → yes (fail closed); a full table → no for an address it does
    /// not hold (M1, see `IP_MAX_ENTRIES`).
    pub fn ip_blocked(&self, ip: IpAddr) -> bool {
        self.ip_blocked_at(ip, Instant::now())
    }

    /// `ip_blocked` at a given time (tests move the clock).
    fn ip_blocked_at(&self, ip: IpAddr, now: Instant) -> bool {
        let ip = ip_key(ip);
        let Ok(mut m) = self.by_ip.lock() else { return true };
        match m.get(&ip) {
            Some(&(n, t)) if now.duration_since(t) < IP_WINDOW => n >= IP_MAX_FAILS,
            Some(_) => {
                m.remove(&ip);
                false
            }
            None => false,
        }
    }

    pub fn record_ip(&self, ip: IpAddr) {
        self.record_ip_at(ip, Instant::now());
    }

    fn record_ip_at(&self, ip: IpAddr, now: Instant) {
        let ip = ip_key(ip);
        let Ok(mut m) = self.by_ip.lock() else { return };
        if m.len() >= IP_MAX_ENTRIES && !m.contains_key(&ip) {
            m.retain(|_, (_, t)| now.duration_since(*t) < IP_WINDOW);
            if m.len() >= IP_MAX_ENTRIES {
                tracing::warn!("authentication failure table full");
                return;
            }
        }
        let e = m.entry(ip).or_insert((0, now));
        if now.duration_since(e.1) >= IP_WINDOW {
            *e = (0, now);
        }
        e.0 += 1;
    }

    /// Has this account exhausted its password attempts (all addresses combined)?
    pub fn account_blocked(&self, user: &str) -> bool {
        self.account_blocked_at(user, Instant::now())
    }

    fn account_blocked_at(&self, user: &str, now: Instant) -> bool {
        self.by_account.blocked_at(user, now, ACCOUNT_MAX_FAILS, ACCOUNT_WINDOW)
    }

    /// Counts a wrong password for an **existing** account (only real names: the table cannot be filled with made-up
    /// ones).
    pub fn record_account(&self, user: &str) {
        self.record_account_at(user, Instant::now());
    }

    fn record_account_at(&self, user: &str, now: Instant) {
        if self.by_account.record_at(user, now, ACCOUNT_WINDOW) == ACCOUNT_MAX_FAILS {
            tracing::warn!(
                user,
                "password: too many failures for this account, locked for 15 minutes"
            );
        }
    }

    /// Has the account exhausted its second-step attempts? Poisoned lock or full table → yes (fail closed).
    pub fn code_blocked(&self, user: &str) -> bool {
        self.code_blocked_at(user, Instant::now())
    }

    fn code_blocked_at(&self, user: &str, now: Instant) -> bool {
        self.code_by_user
            .blocked_at(user, now, USER_MAX_CODE_FAILS, USER_WINDOW)
    }

    pub fn record_code(&self, user: &str) {
        self.record_code_at(user, Instant::now());
    }

    fn record_code_at(&self, user: &str, now: Instant) {
        if self.code_by_user.record_at(user, now, USER_WINDOW) == USER_MAX_CODE_FAILS {
            tracing::warn!(user, "second step: too many wrong codes, blocked for 15 minutes");
        }
    }

    /// Has this share link (its identifier) exhausted its password attempts? Same limits as an address.
    pub fn link_blocked(&self, share_id: &str) -> bool {
        self.by_link
            .blocked_at(share_id, Instant::now(), IP_MAX_FAILS, IP_WINDOW)
    }

    pub fn record_link(&self, share_id: &str) {
        self.by_link.record_at(share_id, Instant::now(), IP_WINDOW);
    }
}

/// User authenticated in a tenant. The only path to the user's data root.
#[derive(Clone, Debug)]
pub struct UserCtx {
    tenant: TenantCtx,
    user: String,
}

impl UserCtx {
    pub fn tenant(&self) -> &TenantCtx {
        &self.tenant
    }
    pub fn user(&self) -> &str {
        &self.user
    }
    /// Opens the user's root (dataset): `openat` relative to the tenant's root.
    pub fn root(&self) -> std::io::Result<Root> {
        let p = SafePath::new(&self.user).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        self.tenant.data_root().open_subdir(&p)
    }
    /// Owner of an **already validated** share link (token, tenant, expiry, revocation): only `web::share`
    /// calls it, to access the shared subtree on behalf of the owner.
    pub(crate) fn share_owner(t: &TenantCtx, user: &str) -> Result<Self> {
        Self::local_admin(t, user)
    }
    /// Local administration (CLI): the machine's operator acts on behalf of `user`.
    pub(crate) fn local_admin(t: &TenantCtx, user: &str) -> Result<Self> {
        if !crate::admin::valid_username(user) {
            return Err(Error::Invalid(format!("invalid user name: {user:?}")));
        }
        Ok(Self {
            tenant: t.clone(),
            user: user.to_owned(),
        })
    }
}

/// Equality of a secret and a value received, in constant time (no timing hint of how many bytes match); a length
/// difference answers at once (lengths are not secret).
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Random secret of `N` bytes, in hexadecimal.
pub fn random_hex<const N: usize>() -> Result<String> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| Error::Invalid(e.to_string()))?;
    Ok(hex(&b))
}

/// Creates a 256-bit app password, shown only once; only its digest is stored.
pub fn new_app_password(db: &Db, t: &TenantCtx, user: &str, label: &str) -> Result<String> {
    let secret = random_hex::<32>()?;
    db.token_add(t, &random_hex::<16>()?, user, &t.mac(secret.as_bytes()), label)?;
    Ok(secret)
}

/// How long a QR-code password waits for its first use.
pub const QR_WAIT: i64 = 10 * 60;

/// App password for the mobile app's QR code: gone after `QR_WAIT` if unused, kept once used; replaces the user's other
/// QR codes not used yet.
pub fn new_qr_password(db: &Db, t: &TenantCtx, user: &str, label: &str) -> Result<String> {
    let secret = random_hex::<32>()?;
    let until = crate::db::now_secs() + QR_WAIT;
    db.token_add_pending(t, (&random_hex::<16>()?, user), &t.mac(secret.as_bytes()), label, until)?;
    Ok(secret)
}

/// What the Nextcloud mobile apps read in a login QR code. User names (`[a-z0-9_.-]`), app passwords (hexadecimal) and
/// the server's address (`scheme://host`) never contain `&`, the separator.
pub fn qr_login(user: &str, password: &str, server: &str) -> String {
    format!("nc://login/user:{user}&password:{password}&server:{server}")
}

/// `Authorization: Basic …` header → (user, secret). Bounded size.
fn parse_basic(h: &str) -> Option<(String, String)> {
    let b64 = h.strip_prefix("Basic ")?.trim();
    if b64.len() > 1024 {
        return None;
    }
    let raw = String::from_utf8(base64ct::Base64::decode_vec(b64).ok()?).ok()?;
    let (u, p) = raw.split_once(':')?;
    Some((u.to_owned(), p.to_owned()))
}

/// The account a verified provider identity (`Verified`) is bound to — active accounts only, by
/// `(issuer, subject)` exactly as the provider stated them. Blocking (database).
pub(crate) fn user_by_oidc(db: &Db, t: &TenantCtx, v: &oidc::Verified) -> Result<Option<UserCtx>> {
    Ok(db.user_by_oidc(t, v.issuer(), v.subject())?.map(|user| UserCtx {
        tenant: t.clone(),
        user,
    }))
}

/// Checks an app password (blocking: database). A human password fails here without ever
/// triggering argon2 (§2): it simply has no recorded HMAC digest.
pub fn verify_basic(db: &Db, t: &TenantCtx, header: &str) -> Result<Option<UserCtx>> {
    let Some((user, secret)) = parse_basic(header) else {
        return Ok(None);
    };
    if !crate::admin::valid_username(&user) {
        return Ok(None);
    }
    Ok(match db.token_user(t, &t.mac(secret.as_bytes()))? {
        Some(owner) if owner == user => Some(UserCtx {
            tenant: t.clone(),
            user,
        }),
        _ => None,
    })
}

// ---------------------------------------------------------------- web sessions (§8)

/// Duration of a web session (absolute, no extension).
pub const SESSION_TTL: i64 = 12 * 3600;

/// Opens a web session after checking the human password. Returns the cookie secret (256 bits);
/// only its HMAC digest is stored.
pub fn new_session(db: &Db, u: &UserCtx) -> Result<String> {
    let secret = random_hex::<32>()?;
    db.session_add(&u.tenant, &u.user, &u.tenant.mac(secret.as_bytes()), SESSION_TTL)?;
    Ok(secret)
}

/// User of a valid session (active account, not expired) in this tenant, and the session's state. Blocking.
pub fn session_user(db: &Db, t: &TenantCtx, secret: &str) -> Result<Option<(UserCtx, crate::db::SessionRow)>> {
    if secret.len() != 64 || !secret.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(None);
    }
    Ok(db.session_user(t, &t.mac(secret.as_bytes()))?.map(|row| {
        (
            UserCtx {
                tenant: t.clone(),
                user: row.user.clone(),
            },
            row,
        )
    }))
}

/// How long an activation link stays valid (it is also single-use).
pub const ACTIVATION_TTL: i64 = 24 * 3600;

/// A new activation link for an active account (`user add`, `user passwd`, `user 2fa-reset`): 256 random bits, returned
/// to be printed once; only its HMAC digest is stored, valid `ACTIVATION_TTL` from `now`; it replaces the account's
/// previous link. Unknown or disabled account: an error.
pub fn activation_issue(db: &Db, t: &TenantCtx, user: &str, now: i64) -> Result<String> {
    let token = random_hex::<32>()?;
    if !db.activation_add(
        t,
        user,
        &t.mac(token.as_bytes()),
        now.saturating_add(ACTIVATION_TTL),
        now,
    )? {
        return Err(Error::Invalid(format!(
            "unknown or disabled account in {}: {user}",
            t.name()
        )));
    }
    Ok(token)
}

/// How long the password stays valid while the second step is awaited.
pub const PENDING_TTL: i64 = 5 * 60;

/// Session opened by the password alone, for an account with two-step verification: it opens only the code page.
pub fn new_pending_session(db: &Db, u: &UserCtx) -> Result<String> {
    let secret = random_hex::<32>()?;
    db.session_add_as(&u.tenant, &u.user, &u.tenant.mac(secret.as_bytes()), PENDING_TTL, true)?;
    Ok(secret)
}

/// Result of a second step.
#[derive(Debug, PartialEq, Eq)]
pub enum Second {
    /// A TOTP code, newer than the last one used.
    Code,
    /// A recovery code, now used up.
    Recovery,
    /// Wrong, already used, malformed, or two-step verification off.
    Wrong,
}

/// Checks a second step typed by the user: 6 digits → TOTP (window ±1 step, each step once), otherwise a recovery
/// code (single use). Blocking (database). `now`: Unix time.
pub fn verify_second(db: &Db, t: &TenantCtx, user: &str, input: &str, now: u64) -> Result<Second> {
    let Some((Some(sealed), last)) = db.totp_get(t, user)? else {
        return Ok(Second::Wrong);
    };
    if let Some(code) = totp::parse_code(input) {
        let Some(secret) = totp::unseal(t, user, &sealed) else {
            return Ok(Second::Wrong);
        };
        return Ok(match totp::check(&secret, code, totp::step(now), last) {
            Some(st) if db.totp_use(t, user, st)? => Second::Code,
            _ => Second::Wrong,
        });
    }
    Ok(match totp::parse_recovery(input) {
        Some(r) if db.recovery_use(t, user, &totp::recovery_mac(t, user, &r))? => Second::Recovery,
        _ => Second::Wrong,
    })
}

/// Confirms the setup of two-step verification with a code from `secret` (the one shown in the QR code); on success
/// stores it sealed and returns the recovery codes to show once. `None`: wrong code, nothing stored. Blocking.
pub fn totp_enable(
    db: &Db,
    t: &TenantCtx,
    user: &str,
    secret: &[u8; totp::SECRET_LEN],
    input: &str,
    now: u64,
) -> Result<Option<Vec<String>>> {
    let Some(st) = totp::parse_code(input).and_then(|c| totp::check(secret, c, totp::step(now), 0)) else {
        return Ok(None);
    };
    let codes = totp::new_recovery_codes()?;
    let macs: Vec<[u8; 32]> = codes
        .iter()
        .filter_map(|c| totp::parse_recovery(c))
        .map(|c| totp::recovery_mac(t, user, &c))
        .collect();
    if !db.totp_enable(t, user, &totp::seal(t, user, secret)?, st, &macs)? {
        return Err(Error::Invalid(format!("unknown account in {}: {user}", t.name())));
    }
    Ok(Some(codes))
}

/// New recovery codes (the old ones stop working), returned to show once. Blocking.
pub fn recovery_renew(db: &Db, t: &TenantCtx, user: &str) -> Result<Vec<String>> {
    let codes = totp::new_recovery_codes()?;
    let macs: Vec<[u8; 32]> = codes
        .iter()
        .filter_map(|c| totp::parse_recovery(c))
        .map(|c| totp::recovery_mac(t, user, &c))
        .collect();
    db.recovery_replace(t, user, &macs)?;
    Ok(codes)
}

pub fn end_session(db: &Db, t: &TenantCtx, secret: &str) -> Result<()> {
    db.session_delete(t, &t.mac(secret.as_bytes()))
}

/// A session's anti-CSRF token: derived from the session secret (nothing to store), required on every modifying action.
pub fn csrf_token(t: &TenantCtx, session_secret: &str) -> String {
    hex(t
        .mac(format!("csrf\0{session_secret}").as_bytes())
        .get(..16)
        .unwrap_or_default())
}

// ---------------------------------------------------------------- share links (§8)

/// A link's public token (128 bits, hexadecimal): HMAC of the link identifier with the tenant's link key. It is not
/// stored (the database only keeps its digest) but can be shown again to its owner.
pub fn share_token(t: &TenantCtx, share_id: &str) -> String {
    hex(t
        .link_mac(format!("share\0{share_id}").as_bytes())
        .get(..16)
        .unwrap_or_default())
}

/// Syntactically valid public token (32 lowercase hexadecimal characters).
pub fn valid_share_token(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Value of the cookie proving that a visitor gave a link's password: bound to the link and its expiry.
pub fn share_pass(t: &TenantCtx, share_id: &str, until: i64) -> String {
    let mac = hex(t
        .link_mac(format!("pass\0{share_id}\0{until}").as_bytes())
        .get(..16)
        .unwrap_or_default());
    format!("{until}.{mac}")
}

pub fn share_pass_ok(t: &TenantCtx, share_id: &str, value: &str, now: i64) -> bool {
    let Some((until, _)) = value.split_once('.') else {
        return false;
    };
    let Ok(until) = until.parse::<i64>() else { return false };
    until > now && constant_time_eq(share_pass(t, share_id, until).as_bytes(), value.as_bytes())
}

/// Value of the cookie marking a download already counted: this link, this file (relative to the link), until `until`.
/// The same guest's following requests (video ranges, resume, Safari's `bytes=0-1` probe) do not count again.
pub fn share_download_pass(t: &TenantCtx, share_id: &str, path: &str, until: i64) -> String {
    let mac = hex(t
        .mac(format!("dl\0{share_id}\0{path}\0{until}").as_bytes())
        .get(..16)
        .unwrap_or_default());
    format!("{until}.{mac}")
}

pub fn share_download_ok(t: &TenantCtx, share_id: &str, path: &str, value: &str, now: i64) -> bool {
    let Some((until, _)) = value.split_once('.') else {
        return false;
    };
    let Ok(until) = until.parse::<i64>() else { return false };
    until > now
        && constant_time_eq(
            share_download_pass(t, share_id, path, until).as_bytes(),
            value.as_bytes(),
        )
}

/// argon2id digest of a link password (concurrency bounded by the caller).
pub fn hash_password(password: &str) -> Result<String> {
    Ok(Argon2::default()
        .hash_password(password.as_bytes())
        .map_err(|e| Error::Invalid(e.to_string()))?
        .to_string())
}

pub fn check_password(hash: &str, password: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
}

/// Dummy digest for nonexistent accounts: same argon2 cost, no existence oracle through timing.
pub fn dummy_hash() -> Result<String> {
    Ok(Argon2::default()
        .hash_password(random_hex::<16>()?.as_bytes())
        .map_err(|e| Error::Invalid(e.to_string()))?
        .to_string())
}

/// Checks a human password (argon2id, expensive: the caller bounds the concurrency). Blocking.
pub fn verify_human(db: &Db, t: &TenantCtx, user: &str, password: &str, dummy: &str) -> Result<Option<UserCtx>> {
    verify_human_known(db, t, user, password, dummy).map(|(u, _)| u)
}

/// `verify_human`, and whether `user` names an active account with a password (what a failure may count against:
/// `Failures::record_account`). Same work either way.
pub fn verify_human_known(
    db: &Db,
    t: &TenantCtx,
    user: &str,
    password: &str,
    dummy: &str,
) -> Result<(Option<UserCtx>, bool)> {
    let stored = if crate::admin::valid_username(user) {
        db.user_password_hash(t, user)?
    } else {
        None
    };
    let hash = stored.as_deref().unwrap_or(dummy);
    let ok = PasswordHash::new(hash)
        .map(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
        .unwrap_or(false);
    let known = stored.is_some();
    Ok((
        (ok && known).then(|| UserCtx {
            tenant: t.clone(),
            user: user.to_owned(),
        }),
        known,
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::tenant::tests::two_tenants;

    /// Test database with `alice` (human password `pw-alice`) in each of the two tenants.
    pub(crate) fn db_with_users(reg: &crate::tenant::Registry, dir: &std::path::Path) -> Db {
        let db = Db::open(&dir.join("app.db")).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let h = Argon2::default().hash_password(b"pw-alice").unwrap().to_string();
        for t in reg.all() {
            db.user_add(t, "alice", &h, false).unwrap();
            db.user_set_password_hash(t, "alice", &h, false).unwrap(); // alice chose it
        }
        db
    }

    fn basic(u: &str, p: &str) -> String {
        format!(
            "Basic {}",
            base64ct::Base64::encode_string(format!("{u}:{p}").as_bytes())
        )
    }

    /// Counted download cookie: bound to the tenant, the link, the file and its duration.
    #[test]
    fn download_pass_is_bound() {
        let (reg, _a, _b) = crate::tenant::tests::two_tenants();
        let (a, b) = (reg.by_name("alpha").unwrap(), reg.by_name("beta").unwrap());
        let v = share_download_pass(&a, "s1", "film.mp4", 2_000);
        assert!(share_download_ok(&a, "s1", "film.mp4", &v, 1_999));
        assert!(!share_download_ok(&a, "s1", "film.mp4", &v, 2_000)); // expired
        assert!(!share_download_ok(&a, "s2", "film.mp4", &v, 1_000)); // other link
        assert!(!share_download_ok(&a, "s1", "autre.mp4", &v, 1_000)); // other file
        assert!(!share_download_ok(&b, "s1", "film.mp4", &v, 1_000)); // other tenant
        let later = v.replacen("2000", "9000", 1);
        assert!(!share_download_ok(&a, "s1", "film.mp4", &later, 1_000)); // duration extended by hand
        assert!(!share_download_ok(&a, "s1", "film.mp4", "x", 1_000));
        assert_ne!(v, share_pass(&a, "s1", 2_000)); // never confused with the password cookie
    }

    #[test]
    fn app_passwords_are_bound_to_tenant_and_user() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = db_with_users(&reg, d.path());
        let (a, b) = (reg.by_name("alpha").unwrap(), reg.by_name("beta").unwrap());
        let pw = new_app_password(&db, &a, "alice", "test").unwrap();
        assert_eq!(pw.len(), 64);
        assert_eq!(
            verify_basic(&db, &a, &basic("alice", &pw)).unwrap().unwrap().user(),
            "alice"
        );
        assert!(verify_basic(&db, &b, &basic("alice", &pw)).unwrap().is_none()); // other tenant
        assert!(verify_basic(&db, &a, &basic("bob", &pw)).unwrap().is_none()); // other user
        assert!(verify_basic(&db, &a, &basic("alice", "pw-alice")).unwrap().is_none()); // human refused
        assert!(verify_basic(&db, &a, &basic("alice", &pw[1..])).unwrap().is_none());
        for bad in [
            "",
            "Basic",
            "Basic !!!",
            "Bearer x",
            &format!("Basic {}", "A".repeat(2000)),
        ] {
            assert!(verify_basic(&db, &a, bad).unwrap().is_none());
        }
        // The secret is never stored in clear.
        assert_ne!(t_mac_hex(&a, &pw), pw);
    }

    fn t_mac_hex(t: &TenantCtx, s: &str) -> String {
        hex(&t.mac(s.as_bytes()))
    }

    #[test]
    fn failures_are_limited_per_ip_and_bounded() {
        let f = Failures::default();
        let (a, b): (IpAddr, IpAddr) = ("192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap());
        for _ in 0..IP_MAX_FAILS {
            assert!(!f.ip_blocked(a));
            f.record_ip(a);
        }
        assert!(f.ip_blocked(a));
        assert!(!f.ip_blocked(b)); // another IP is not penalized
        // An account: blocked after its failures, all addresses combined; another account is not.
        for _ in 0..ACCOUNT_MAX_FAILS {
            assert!(!f.account_blocked("alice"));
            f.record_account("alice");
        }
        assert!(f.account_blocked("alice") && !f.account_blocked("bob"));
        // Full table of live addresses (M1): it never grows past its bound, an address it holds keeps its block, and
        // an address it does not know is let through — refusing it would close the door to everyone. The other limits
        // (per account, per link, per code) still bound what that address may try.
        let g = Failures::default();
        for _ in 0..IP_MAX_FAILS {
            g.record_ip(a);
        }
        for i in 0..IP_MAX_ENTRIES as u32 {
            g.record_ip(IpAddr::from(i.to_be_bytes()));
        }
        g.record_ip("198.51.100.1".parse().unwrap());
        assert_eq!(g.by_ip.lock().unwrap().len(), IP_MAX_ENTRIES);
        assert!(
            !g.ip_blocked("198.51.100.1".parse().unwrap()),
            "a new address is not locked out"
        );
        assert!(g.ip_blocked(a), "a blocked address stays blocked");
    }

    /// The known-device mark (set after a right password): only for its account and its tenant, compared in full.
    #[test]
    fn known_device_mark_is_bound() {
        let (reg, _a, _b) = two_tenants();
        let (a, b) = (reg.by_name("alpha").unwrap(), reg.by_name("beta").unwrap());
        let m = known_device(&a, "alice");
        assert!(known_device_ok(&a, "alice", &m));
        assert!(!known_device_ok(&a, "bob", &m) && !known_device_ok(&b, "alice", &m));
        assert!(!known_device_ok(&a, "alice", "") && !known_device_ok(&a, "alice", &m[1..]));
        assert!(!known_device_ok(&a, "alice", &format!("{m}0")));
    }

    /// Written down, as mutation testing showed the tests only used them symbolically: the policy's durations, and the
    /// `Authorization` size bound exactly at 1024 characters.
    #[test]
    fn policy_values_and_header_bound() {
        assert_eq!((IP_WINDOW.as_secs(), QR_WAIT, SESSION_TTL), (300, 600, 12 * 3600));
        let header = |len: usize| {
            let raw = format!("alice:{}", "x".repeat(len / 4 * 3 - 6));
            let b64 = base64ct::Base64::encode_string(raw.as_bytes());
            assert_eq!(b64.len(), len);
            format!("Basic {b64}")
        };
        assert!(parse_basic(&header(1024)).is_some());
        assert!(parse_basic(&header(1028)).is_none());
        // Nonexistent accounts are checked against a real argon2id digest: same work, no existence oracle by timing.
        let dummy = dummy_hash().unwrap();
        let h = PasswordHash::new(&dummy).unwrap();
        assert_eq!(h.algorithm.as_str(), "argon2id");
        assert!(!check_password(&dummy, "anything"));
    }

    /// A full table whose entries have all expired makes room for a new IP right at the end of the window, on the
    /// recording path itself.
    #[test]
    fn full_table_frees_expired_entries_when_recording() {
        let f = Failures::default();
        let t0 = Instant::now();
        for i in 0..IP_MAX_ENTRIES as u32 {
            f.record_ip_at(IpAddr::from(i.to_be_bytes()), t0);
        }
        f.record_ip_at("198.51.100.3".parse().unwrap(), t0 + IP_WINDOW);
        assert_eq!(f.by_ip.lock().unwrap().len(), 1);
    }

    /// The windows end: a blocked IP and a blocked tenant get their attempts back, from zero, once the window has passed,
    /// never a second before; an IP's old failures do not add up with new ones; the full table frees expired entries.
    #[test]
    fn failure_windows_expire_exactly() {
        let f = Failures::default();
        let ip: IpAddr = "192.0.2.9".parse().unwrap();
        let t0 = Instant::now();
        for _ in 0..IP_MAX_FAILS {
            f.record_ip_at(ip, t0);
        }
        let just_before = t0 + IP_WINDOW - Duration::from_millis(1);
        assert!(f.ip_blocked_at(ip, t0) && f.ip_blocked_at(ip, just_before));
        assert!(!f.ip_blocked_at(ip, t0 + IP_WINDOW)); // expired: forgotten
        // After the window, failures count from zero again: one is not enough to block.
        f.record_ip_at(ip, t0 + IP_WINDOW);
        assert!(!f.ip_blocked_at(ip, t0 + IP_WINDOW));
        // A stale counter (the entry kept, its window over) restarts at one on the next failure.
        let stale: IpAddr = "192.0.2.10".parse().unwrap();
        for _ in 0..IP_MAX_FAILS {
            f.record_ip_at(stale, t0);
        }
        f.record_ip_at(stale, t0 + IP_WINDOW);
        assert_eq!(f.by_ip.lock().unwrap()[&stale].0, 1);
        // An account's failures: same rule over their own window.
        for _ in 0..ACCOUNT_MAX_FAILS {
            f.record_account_at("alice", t0);
        }
        assert!(f.account_blocked_at("alice", t0 + ACCOUNT_WINDOW - Duration::from_millis(1)));
        assert!(!f.account_blocked_at("alice", t0 + ACCOUNT_WINDOW));
        f.record_account_at("alice", t0 + ACCOUNT_WINDOW);
        assert!(!f.account_blocked_at("alice", t0 + ACCOUNT_WINDOW));
        assert_eq!((ACCOUNT_MAX_FAILS, ACCOUNT_WINDOW.as_secs()), (10, 15 * 60));
        // Full table of old entries: a new IP gets in once they have expired.
        let g = Failures::default();
        for i in 0..IP_MAX_ENTRIES as u32 {
            g.record_ip_at(IpAddr::from(i.to_be_bytes()), t0);
        }
        let late = t0 + IP_WINDOW;
        let new: IpAddr = "198.51.100.2".parse().unwrap();
        assert!(!g.ip_blocked_at(new, late));
        g.record_ip_at(new, late);
        assert_eq!(g.by_ip.lock().unwrap().len(), 1);
    }

    /// An app password only opens its own account: another user's, with this user's name, is refused; so are a hostile
    /// user name and a malformed header. A link password cookie must be well formed.
    #[test]
    fn app_password_of_another_user_is_refused() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = db_with_users(&reg, d.path());
        let a = reg.by_name("alpha").unwrap();
        db.user_add(&a, "bob", "h", false).unwrap();
        let bob = new_app_password(&db, &a, "bob", "x").unwrap();
        let basic = |u: &str, p: &str| {
            format!(
                "Basic {}",
                base64ct::Base64::encode_string(format!("{u}:{p}").as_bytes())
            )
        };
        let who = |h: &str| verify_basic(&db, &a, h).unwrap().map(|u| u.user().to_owned());
        assert_eq!(who(&basic("bob", &bob)).as_deref(), Some("bob"));
        assert_eq!(who(&basic("alice", &bob)), None);
        assert_eq!(who(&basic("../alice", &bob)), None);
        for bad in [
            "Basic",
            "Basic !!!",
            "Bearer abc",
            &format!("Basic {}", "A".repeat(2000)),
        ] {
            assert_eq!(who(bad), None, "{bad}");
        }
        assert!(UserCtx::local_admin(&a, "../x").is_err());
        assert!(!share_pass_ok(&a, "id1", "sans-point", 0) && !share_pass_ok(&a, "id1", "x.y", 0));
    }

    /// QR-code password: works at once, kept once used, gone after `QR_WAIT` if unused; a new QR code cancels the
    /// previous one not used yet, never a used one.
    #[test]
    fn qr_password_waits_ten_minutes_for_its_first_use() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = db_with_users(&reg, d.path());
        let a = reg.by_name("alpha").unwrap();
        let auth = |s: &str| {
            let h = format!(
                "Basic {}",
                base64ct::Base64::encode_string(format!("alice:{s}").as_bytes())
            );
            verify_basic(&db, &a, &h).unwrap().map(|u| u.user().to_owned())
        };
        let pending = |db: &Db| {
            db.token_list(&a, "alice")
                .unwrap()
                .iter()
                .filter(|t| t.expires_at.is_some())
                .count()
        };
        let used = new_qr_password(&db, &a, "alice", "QR").unwrap();
        assert_eq!(pending(&db), 1);
        assert_eq!(auth(&used).as_deref(), Some("alice")); // first use: kept from now on
        assert_eq!(pending(&db), 0);
        let unused = new_qr_password(&db, &a, "alice", "QR").unwrap();
        let again = new_qr_password(&db, &a, "alice", "QR").unwrap();
        assert_eq!(pending(&db), 1); // the second QR code cancelled the first
        assert_eq!((auth(&unused), auth(&used).is_some()), (None, true));
        // Ten minutes later, unused: refused and removed from the list.
        db.raw(
            "UPDATE app_token SET expires_at = expires_at - 601 WHERE tenant_id = 'alpha' AND expires_at IS NOT NULL",
        );
        assert_eq!(auth(&again), None);
        assert_eq!(db.token_list(&a, "alice").unwrap().len(), 1);
        assert_eq!(auth(&used).as_deref(), Some("alice"));
    }

    #[test]
    fn sessions_and_share_tokens() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = db_with_users(&reg, d.path());
        let (a, b) = (reg.by_name("alpha").unwrap(), reg.by_name("beta").unwrap());
        let u = UserCtx::local_admin(&a, "alice").unwrap();
        let s = new_session(&db, &u).unwrap();
        let (u, row) = session_user(&db, &a, &s).unwrap().unwrap();
        assert!(u.user() == "alice" && !row.must_change && !row.pending && !row.totp);
        assert!(session_user(&db, &b, &s).unwrap().is_none()); // other tenant
        assert!(session_user(&db, &a, "zz").unwrap().is_none());
        assert_ne!(csrf_token(&a, &s), csrf_token(&b, &s));
        end_session(&db, &a, &s).unwrap();
        assert!(session_user(&db, &a, &s).unwrap().is_none());
        // Link token: stable, specific to the tenant, 128 bits.
        let tok = share_token(&a, "id1");
        assert!(valid_share_token(&tok) && tok == share_token(&a, "id1") && tok != share_token(&b, "id1"));
        assert!(!valid_share_token("../x") && !valid_share_token(&tok.to_uppercase()));
        // Password cookie: bound to the link and its expiry.
        let c = share_pass(&a, "id1", 1000);
        assert!(share_pass_ok(&a, "id1", &c, 999));
        assert!(!share_pass_ok(&a, "id1", &c, 1000)); // expired
        assert!(!share_pass_ok(&a, "id2", &c, 999)); // other link
        assert!(!share_pass_ok(&b, "id1", &c, 999)); // other tenant
        assert!(!share_pass_ok(&a, "id1", "2000.00", 999)); // forged expiry
        // One character changed, cut, or added: refused (compared in constant time, whole value).
        for f in [
            forge_last(&c),
            c.get(..c.len() - 1).unwrap().to_owned(),
            format!("{c}0"),
            String::new(),
        ] {
            assert!(!share_pass_ok(&a, "id1", &f, 999), "{f}");
        }
        let d = share_download_pass(&a, "id1", "f", 1000);
        for f in [
            forge_last(&d),
            d.get(..d.len() - 1).unwrap().to_owned(),
            format!("{d}0"),
        ] {
            assert!(!share_download_ok(&a, "id1", "f", &f, 999), "{f}");
        }
    }

    /// The value with its last hexadecimal character changed.
    fn forge_last(v: &str) -> String {
        let (head, last) = v.split_at(v.len() - 1);
        format!("{head}{}", if last == "0" { "1" } else { "0" })
    }

    /// Address keys: IPv4 itself (also IPv4-mapped), IPv6 by its /64.
    #[test]
    fn ip_key_bounds() {
        let k = |s: &str| ip_key(s.parse().unwrap());
        assert_eq!(k("192.0.2.7"), k("::ffff:192.0.2.7"));
        assert_ne!(k("192.0.2.7"), k("192.0.2.8"));
        assert_eq!(k("2001:db8:1:2:aaaa::1"), k("2001:db8:1:2:ffff:ffff:ffff:ffff"));
        assert_eq!(k("2001:db8:1:2:aaaa::1"), "2001:db8:1:2::".parse::<IpAddr>().unwrap());
        assert_ne!(k("2001:db8:1:2::1"), k("2001:db8:1:3::1"));
    }

    /// An activation link: 256 random bits, only its digest stored, valid `ACTIVATION_TTL`; refused for an unknown or
    /// disabled account; two links are never the same.
    #[test]
    fn activation_issue_bounds() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = db_with_users(&reg, d.path());
        let a = reg.by_name("alpha").unwrap();
        let t1 = activation_issue(&db, &a, "alice", 1_000).unwrap();
        assert!(t1.len() == 64 && t1.bytes().all(|b| b.is_ascii_hexdigit()));
        let row = db
            .activation_find(&a, &a.mac(t1.as_bytes()), 1_000 + ACTIVATION_TTL - 1)
            .unwrap();
        assert_eq!(row.map(|r| r.user).as_deref(), Some("alice"));
        assert!(
            db.activation_find(&a, &a.mac(t1.as_bytes()), 1_000 + ACTIVATION_TTL)
                .unwrap()
                .is_none()
        );
        assert_eq!(ACTIVATION_TTL, 24 * 3600);
        assert!(activation_issue(&db, &a, "ghost", 1_000).is_err());
        db.user_set_active(&a, "alice", false).unwrap();
        assert!(activation_issue(&db, &a, "alice", 1_000).is_err());
        db.user_set_active(&a, "alice", true).unwrap();
        assert_ne!(activation_issue(&db, &a, "alice", 1_000).unwrap(), t1);
    }

    /// Share links have their own counters, by their whole identifier: two links that start alike never share one, and
    /// no link touches an address's counter.
    #[test]
    fn link_failures_are_per_link() {
        let f = Failures::default();
        let (one, two) = ("abcd1111111111111111111111111111", "abcd2222222222222222222222222222");
        for _ in 0..IP_MAX_FAILS {
            assert!(!f.link_blocked(one));
            f.record_link(one);
        }
        assert!(f.link_blocked(one));
        assert!(!f.link_blocked(two));
        assert!(!f.ip_blocked("2001:db8::1".parse().unwrap()) && !f.ip_blocked("192.0.2.1".parse().unwrap()));
    }

    /// Failures from one IPv6 /64 add up whatever the address inside it; the next /64 is not touched.
    #[test]
    fn ipv6_failures_count_per_64() {
        let f = Failures::default();
        let now = Instant::now();
        for i in 1..=IP_MAX_FAILS {
            assert!(!f.ip_blocked_at(format!("2001:db8::{i:x}").parse().unwrap(), now));
            f.record_ip_at(format!("2001:db8::{i:x}").parse().unwrap(), now);
        }
        assert!(f.ip_blocked_at("2001:db8::ffff:1".parse().unwrap(), now));
        assert!(!f.ip_blocked_at("2001:db8:0:1::1".parse().unwrap(), now));
    }

    proptest::proptest! {
        /// Any two IPv6 addresses share a key exactly when they share their first 64 bits; an IPv4 key is itself.
        #[test]
        fn ip_key_is_the_64(a: u128, b: u128, v4: u32) {
            use std::net::{Ipv4Addr, Ipv6Addr};
            let (x, y) = (Ipv6Addr::from(a), Ipv6Addr::from(b));
            if x.to_ipv4_mapped().is_none() && y.to_ipv4_mapped().is_none() {
                proptest::prop_assert_eq!(ip_key(x.into()) == ip_key(y.into()), a >> 64 == b >> 64);
            }
            proptest::prop_assert_eq!(ip_key(Ipv4Addr::from(v4).into()), IpAddr::V4(Ipv4Addr::from(v4)));
            proptest::prop_assert_eq!(ip_key(ip_key(x.into())), ip_key(x.into()));
        }
    }

    /// Constant-time equality: equal values only; a different byte anywhere, a prefix, a longer value: not equal.
    #[test]
    fn constant_time_eq_bounds() {
        assert!(constant_time_eq(b"", b"") && constant_time_eq(b"abc", b"abc"));
        for (x, y) in [
            (&b"abc"[..], &b"xbc"[..]),
            (b"abc", b"abx"),
            (b"abc", b"ab"),
            (b"ab", b"abc"),
            (b"", b"a"),
        ] {
            assert!(!constant_time_eq(x, y), "{x:?} {y:?}");
        }
    }

    proptest::proptest! {
        /// Constant-time equality answers exactly as `==`.
        #[test]
        fn constant_time_eq_is_equality(a in proptest::collection::vec(0u8..4, 0..8), b in proptest::collection::vec(0u8..4, 0..8)) {
            proptest::prop_assert_eq!(constant_time_eq(&a, &b), a == b);
            proptest::prop_assert!(constant_time_eq(&a, &a));
        }
    }

    /// Second-step limit per account: 4 failures pass, the 5th blocks, for 15 minutes, for this account only, all IPs
    /// combined; the table is bounded and fails closed when full of live entries.
    #[test]
    fn code_failures_are_limited_per_account() {
        let f = Failures::default();
        let t0 = Instant::now();
        for _ in 0..USER_MAX_CODE_FAILS - 1 {
            f.record_code_at("alice", t0);
        }
        assert!(!f.code_blocked_at("alice", t0)); // below
        f.record_code_at("alice", t0);
        assert!(f.code_blocked_at("alice", t0)); // at
        assert!(f.code_blocked_at("alice", t0 + USER_WINDOW - Duration::from_secs(1)));
        assert!(!f.code_blocked_at("bob", t0)); // another account
        assert!(!f.code_blocked_at("alice", t0 + USER_WINDOW)); // window over
        f.record_code_at("alice", t0 + USER_WINDOW);
        assert!(!f.code_blocked_at("alice", t0 + USER_WINDOW)); // counting again from 1
        let g = Failures::default();
        for i in 0..IP_MAX_ENTRIES {
            g.record_code_at(&format!("u{i}"), t0);
        }
        assert!(g.code_blocked_at("newcomer", t0)); // full of live entries: closed
        assert!(!g.code_blocked_at("newcomer", t0 + USER_WINDOW)); // they expired: room again
    }

    /// The second-step policy in plain figures: the tests above use the constants, so a wrong value would not show.
    #[test]
    fn second_step_policy_values() {
        assert_eq!(USER_MAX_CODE_FAILS, 5);
        assert_eq!(USER_WINDOW, Duration::from_secs(900));
        assert_eq!(PENDING_TTL, 300);
    }

    /// The per-account table when full: a new account is not recorded while every entry is live, an account already
    /// there still counts, expired entries make room (exactly at the end of the window, not a second before).
    #[test]
    fn code_failure_table_is_bounded() {
        let f = Failures::default();
        let t0 = Instant::now();
        for i in 0..IP_MAX_ENTRIES - 1 {
            f.record_code_at(&format!("u{i}"), t0);
        }
        let has = |u: &str| f.code_by_user.0.lock().unwrap().get(u).map(|e| e.0);
        let len = || f.code_by_user.0.lock().unwrap().len();
        f.record_code_at("last", t0); // one place left: taken
        assert_eq!((has("last"), len()), (Some(1), IP_MAX_ENTRIES));
        f.record_code_at("late", t0); // full of live entries
        assert_eq!((has("late"), len()), (None, IP_MAX_ENTRIES));
        f.record_code_at("u0", t0); // already there: counted, even when full
        assert_eq!(has("u0"), Some(2));
        f.record_code_at("late", t0 + USER_WINDOW - Duration::from_secs(1)); // still live
        assert_eq!((has("late"), len()), (None, IP_MAX_ENTRIES));
        f.record_code_at("late", t0 + USER_WINDOW); // all expired: room again
        assert_eq!((has("late"), len()), (Some(1), 1));
    }

    /// A user with two-step verification on (secret `[7; 20]`, set up at step `now - 1`); returns the recovery codes.
    pub(crate) fn enable_totp(db: &Db, t: &TenantCtx, user: &str) -> Vec<String> {
        // The tests that follow call `code_at` against the server's real clock: they start at the beginning of a
        // 30-second step, so that "the current code" stays the same code for 20 s or more (a test crossing a step
        // saw its replayed code accepted as a new one).
        let left = 30 - totp::now() % 30;
        if left < 20 {
            std::thread::sleep(Duration::from_secs(left));
        }
        let s = [7u8; totp::SECRET_LEN];
        let now = totp::now();
        let code = format!("{:06}", totp::hotp(&s, totp::step(now) - 1));
        totp_enable(db, t, user, &s, &code, now).unwrap().unwrap()
    }

    /// The code of `[7; 20]` at the current step + `k`.
    pub(crate) fn code_at(k: i64) -> String {
        let st = totp::step(totp::now()).checked_add_signed(k).unwrap();
        format!("{:06}", totp::hotp(&[7u8; totp::SECRET_LEN], st))
    }

    /// Set up: a wrong code stores nothing; the right one stores the secret sealed and 10 recovery codes, and its step
    /// cannot be used again; the other tenant's alice and bob are untouched.
    #[test]
    fn totp_setup() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = db_with_users(&reg, d.path());
        let (a, b) = (reg.by_name("alpha").unwrap(), reg.by_name("beta").unwrap());
        db.user_add(&a, "bob", "h", false).unwrap();
        let s = [7u8; totp::SECRET_LEN];
        let now = totp::now();
        let wrong = format!("{:06}", (totp::hotp(&s, totp::step(now)) + 1) % 1_000_000);
        assert_eq!(totp_enable(&db, &a, "alice", &s, &wrong, now).unwrap(), None);
        assert_eq!(totp_enable(&db, &a, "alice", &s, "abc", now).unwrap(), None);
        assert_eq!(db.totp_get(&a, "alice").unwrap(), Some((None, 0)));
        let codes = enable_totp(&db, &a, "alice");
        let now = totp::now(); // enable_totp may wait for a fresh time step
        assert_eq!(codes.len(), totp::RECOVERY_CODES);
        assert_eq!(db.recovery_count(&a, "alice").unwrap(), 10);
        let (sealed, last) = db.totp_get(&a, "alice").unwrap().unwrap();
        assert_eq!(totp::unseal(&a, "alice", &sealed.unwrap()), Some(s));
        assert_eq!(last, totp::step(now) - 1);
        assert_eq!(
            verify_second(&db, &a, "alice", &code_at(-1), now).unwrap(),
            Second::Wrong
        ); // the setup code
        for (t, u) in [(&b, "alice"), (&a, "bob")] {
            assert_eq!(db.totp_get(t, u).unwrap().map(|x| x.0.is_some()), Some(false));
            assert_eq!(db.recovery_count(t, u).unwrap(), 0);
            assert_eq!(verify_second(&db, t, u, &code_at(0), now).unwrap(), Second::Wrong);
        }
        assert!(totp_enable(&db, &a, "carol", &s, &code_at(0), now).is_err()); // unknown account
    }

    /// Second step: each TOTP step once, each recovery code once; another user's or tenant's codes never work; a
    /// disabled account or one without two-step verification never passes.
    #[test]
    fn second_step() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = db_with_users(&reg, d.path());
        let (a, b) = (reg.by_name("alpha").unwrap(), reg.by_name("beta").unwrap());
        let now = totp::now();
        assert_eq!(
            verify_second(&db, &a, "alice", &code_at(0), now).unwrap(),
            Second::Wrong
        ); // off
        let codes = enable_totp(&db, &a, "alice");
        let now = totp::now(); // enable_totp may wait for a fresh time step
        let v = |input: &str| verify_second(&db, &a, "alice", input, now).unwrap();
        assert_eq!(v(&code_at(0)), Second::Code);
        assert_eq!(v(&code_at(0)), Second::Wrong); // replay
        assert_eq!(v(&code_at(-1)), Second::Wrong); // older than the last used
        assert_eq!(v(&code_at(2)), Second::Wrong); // too far ahead
        assert_eq!(v(&code_at(1)), Second::Code);
        assert_eq!(v(""), Second::Wrong);
        assert_eq!(v("garbage!"), Second::Wrong);
        let first = codes.first().unwrap();
        assert_eq!(verify_second(&db, &b, "alice", first, now).unwrap(), Second::Wrong); // other tenant
        assert_eq!(v(&first.to_uppercase().replace('-', " ")), Second::Recovery); // typed loosely
        assert_eq!(v(first), Second::Wrong); // used up
        assert_eq!(db.recovery_count(&a, "alice").unwrap(), 9);
        // New codes: the old ones stop working.
        let old = codes.get(1).unwrap();
        let new = recovery_renew(&db, &a, "alice").unwrap();
        assert_eq!(v(old), Second::Wrong);
        assert_eq!(v(new.first().unwrap()), Second::Recovery);
        // Disabled account: nothing passes; enabled again, it works again.
        db.user_set_active(&a, "alice", false).unwrap();
        assert_eq!(v(new.get(1).unwrap()), Second::Wrong);
        db.user_set_active(&a, "alice", true).unwrap();
        assert_eq!(v(new.get(1).unwrap()), Second::Recovery);
        // Off: secret and codes gone.
        assert!(db.totp_disable(&a, "alice").unwrap());
        assert_eq!(db.recovery_count(&a, "alice").unwrap(), 0);
        assert_eq!(v(new.get(2).unwrap()), Second::Wrong);
        db.totp_rewind(&a, "alice");
        assert_eq!(v(&code_at(0)), Second::Wrong);
    }

    /// A step of the model below.
    #[derive(Clone, Debug)]
    enum Op {
        /// Set up with the code of step now + k (k in -2..=2).
        Enable(i8),
        /// Sign in with the code of step now + k.
        Code(i8),
        /// Sign in with recovery code n (of those given last), or a made-up one.
        Recovery(usize),
        Renew,
        Disable,
        /// The clock moves forward by this many steps.
        Tick(u8),
    }

    fn op() -> impl proptest::strategy::Strategy<Value = Op> {
        use proptest::prelude::*;
        prop_oneof![
            (-2i8..=2).prop_map(Op::Enable),
            (-2i8..=2).prop_map(Op::Code),
            (0usize..12).prop_map(Op::Recovery),
            Just(Op::Renew),
            Just(Op::Disable),
            (0u8..3).prop_map(Op::Tick),
        ]
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]
        /// Model of two-step verification for one account: a code passes only when on, inside ±1 step and newer than
        /// the last one used; a recovery code passes once and only from the latest set; set up only with a right code;
        /// off drops everything. The other tenant's alice never changes.
        #[test]
        fn second_step_model(ops in proptest::collection::vec(op(), 1..30)) {
            use proptest::prelude::*;
            let (reg, _a, _b) = two_tenants();
            let d = tempfile::tempdir().unwrap();
            let db = db_with_users(&reg, d.path());
            let (a, b) = (reg.by_name("alpha").unwrap(), reg.by_name("beta").unwrap());
            let s = [9u8; totp::SECRET_LEN];
            let mut now = 1_700_000_000u64;
            // Model: on, last step used, recovery codes still valid, the latest set given.
            let (mut on, mut last, mut valid, mut given) = (false, 0u64, Vec::<String>::new(), Vec::<String>::new());
            for op in ops {
                let st = totp::step(now);
                let code = |k: i8| format!("{:06}", totp::hotp(&s, st.checked_add_signed(i64::from(k)).unwrap()));
                match op {
                    Op::Enable(k) => {
                        let r = totp_enable(&db, &a, "alice", &s, &code(k), now).unwrap();
                        // The window only (no step used yet); a code two steps away may collide with one inside.
                        let expect = totp::check(&s, totp::hotp(&s, st.checked_add_signed(i64::from(k)).unwrap()), st, 0);
                        prop_assert_eq!(r.is_some(), expect.is_some());
                        if k.unsigned_abs() <= 1 {
                            prop_assert!(r.is_some());
                        }
                        if let (Some(c), Some(x)) = (r, expect) {
                            (on, last) = (true, x);
                            valid = c.clone();
                            given = c;
                        }
                    }
                    Op::Code(k) => {
                        let c = totp::hotp(&s, st.checked_add_signed(i64::from(k)).unwrap());
                        let expect = on.then(|| totp::check(&s, c, st, last)).flatten();
                        let r = verify_second(&db, &a, "alice", &code(k), now).unwrap();
                        prop_assert_eq!(r == Second::Code, expect.is_some());
                        if let Some(x) = expect {
                            last = x;
                        }
                    }
                    Op::Recovery(n) => {
                        let input = given.get(n).cloned().unwrap_or_else(|| "zzzz-zzzz".into());
                        let expect = on && valid.contains(&input);
                        let r = verify_second(&db, &a, "alice", &input, now).unwrap();
                        prop_assert_eq!(r == Second::Recovery, expect);
                        valid.retain(|c| *c != input || !expect);
                    }
                    Op::Renew => {
                        if on {
                            let c = recovery_renew(&db, &a, "alice").unwrap();
                            valid = c.clone();
                            given = c;
                        }
                    }
                    Op::Disable => {
                        db.totp_disable(&a, "alice").unwrap();
                        (on, last) = (false, 0);
                        valid.clear();
                    }
                    Op::Tick(n) => now += 30 * u64::from(n),
                }
                let row = db.totp_get(&a, "alice").unwrap().unwrap();
                prop_assert_eq!(row.0.is_some(), on);
                prop_assert_eq!(row.1, last);
                prop_assert_eq!(db.recovery_count(&a, "alice").unwrap() as usize, valid.len());
                prop_assert_eq!(db.totp_get(&b, "alice").unwrap(), Some((None, 0)));
            }
        }
    }

    #[test]
    fn human_password() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = db_with_users(&reg, d.path());
        let a = reg.by_name("alpha").unwrap();
        let dummy = dummy_hash().unwrap();
        assert!(verify_human(&db, &a, "alice", "pw-alice", &dummy).unwrap().is_some());
        assert!(verify_human(&db, &a, "alice", "nope", &dummy).unwrap().is_none());
        assert!(verify_human(&db, &a, "ghost", "pw-alice", &dummy).unwrap().is_none());
        assert!(verify_human(&db, &a, "../x", "pw-alice", &dummy).unwrap().is_none());
    }
}
