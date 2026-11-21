//! The single administration service layer (§3): the CLI is a thin adapter over it.

use crate::db::{Db, UserRow};
use crate::fs::SafePath;
use crate::tenant::TenantCtx;
use crate::{Error, Result};
use argon2::Argon2;
use argon2::password_hash::PasswordHasher;

/// User name: `[a-z0-9_.-]{1,64}`, does not start with `.` (it is also a folder name).
pub fn valid_username(u: &str) -> bool {
    (1..=64).contains(&u.len())
        && !u.starts_with('.')
        && u.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-'))
}

/// Adds a user. The dataset `<data_root>/<user>` must exist **and be a distinct mount point**
/// (created by the administrator on the host, §0.3): the application never runs `zfs`.
/// Returns the generated human password (128 bits), to be shown only once.
pub fn user_add(db: &Db, t: &TenantCtx, user: &str, admin: bool) -> Result<String> {
    user_dataset(t, user)?;
    let password = crate::auth::random_hex::<16>()?;
    db.user_add(t, user, &hash(&password)?, admin)?;
    Ok(password)
}

/// Adds an account that signs in only through a provider identity (`[tenant.oidc]`, then `user oidc-link`): no
/// password is generated, and neither `/login` nor the Login Flow form can open it (`verify_human` refuses NULL).
pub fn user_add_oidc(db: &Db, t: &TenantCtx, user: &str, admin: bool) -> Result<()> {
    user_dataset(t, user)?;
    db.user_add_oidc(t, user, admin)
}

/// `user oidc-link`: binds a provider identity to an account. `issuer` is the tenant's configured one (byte for byte,
/// as the provider publishes it), `subject` the `sub` the administrator got from the provider. Never a name or an
/// e-mail claim: that would be a cross-tenant hole (§9).
pub fn user_oidc_link(db: &Db, t: &TenantCtx, user: &str, issuer: &str, subject: &str) -> Result<()> {
    if !valid_username(user) {
        return Err(Error::Invalid(format!("invalid user name: {user:?}")));
    }
    if !crate::auth::oidc::valid_subject(subject) {
        return Err(Error::Invalid(format!(
            "invalid subject: 1 to {} visible ASCII characters expected",
            crate::auth::oidc::SUBJECT_MAX
        )));
    }
    if crate::auth::oidc::HttpsUrl::parse(issuer).is_err() {
        return Err(Error::Invalid(format!("invalid issuer: {issuer:?}")));
    }
    db.user_oidc_link(t, user, issuer, subject)
}

/// The dataset of an account must exist, be a distinct one and be usable: checked by `user add` and
/// `user add --oidc` alike.
fn user_dataset(t: &TenantCtx, user: &str) -> Result<()> {
    if !valid_username(user) {
        return Err(Error::Invalid(format!("invalid user name: {user:?}")));
    }
    let root = t.data_root().open_subdir(&SafePath::new(user)?).map_err(|e| {
        Error::Invalid(format!(
            "{}/{user} not found ({e}): create the user's ZFS dataset first",
            t.name()
        ))
    })?;
    if root.dev()? == t.data_root().dev()? {
        return Err(Error::Invalid(format!(
            "{}/{user} is not a distinct dataset: create a child dataset (per-user ZFS quota, §4)",
            t.name()
        )));
    }
    root.check_storage()?;
    root.ensure_layout()?;
    Ok(())
}

/// The crate's default parameters: argon2id, m=19 MiB, t=2, p=1 (OWASP, §0.4).
fn hash(password: &str) -> Result<String> {
    Ok(Argon2::default()
        .hash_password(password.as_bytes())
        .map_err(|e| Error::Invalid(e.to_string()))?
        .to_string())
}

/// Floor of `min_password` (configuration): no human password below it, whatever the setting.
pub const MIN_PASSWORD: usize = 10;

/// Why a chosen human password is refused (the message is the English key of `i18n`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Weak {
    Short,
    Name,
    Trivial,
    Reused,
}

impl Weak {
    pub fn message(self) -> &'static str {
        match self {
            Weak::Short => "New password too short: nothing was changed.",
            Weak::Name => "The new password must not contain the account or tenant name: nothing was changed.",
            Weak::Trivial => {
                "New password too easy to guess (repeated characters, sequence or keyboard row): nothing was changed."
            }
            Weak::Reused => "The new password must differ from the current one: nothing was changed.",
        }
    }
}

/// Rows whose runs are refused (doubled: a run may wrap around).
const ROWS: [&str; 5] = [
    "01234567890123456789",
    "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
    "azertyuiopqsdfghjklmwxcvbnazertyuiopqsdfghjklmwxcvbn",
    "qwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnm",
    "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p",
];

/// Length and composition rules (NIST SP 800-63B: length and refusal of trivial passwords, no character classes).
/// `min` is clamped to `MIN_PASSWORD`. The reuse of the current password is checked by `user_passwd`.
pub fn weakness(password: &str, user: &str, tenant: &str, min: usize) -> Option<Weak> {
    let n = password.chars().count();
    if n < min.max(MIN_PASSWORD) {
        return Some(Weak::Short);
    }
    let low = password.to_lowercase();
    if [user, tenant]
        .iter()
        .any(|x| x.chars().count() >= 3 && low.contains(&x.to_lowercase()))
    {
        return Some(Weak::Name);
    }
    let mut distinct: Vec<char> = low.chars().collect();
    distinct.sort_unstable();
    distinct.dedup();
    let rev: String = low.chars().rev().collect();
    let in_row = |s: &str| ROWS.iter().any(|r| r.contains(s));
    // Fewer than 4 distinct characters ("abababababab"), or a run of a row read either way.
    (distinct.len() < 4 || in_row(&low) || in_row(&rev)).then_some(Weak::Trivial)
}

/// Changes the human password (web login, Login Flow). `None`: generates one (128 bits), returned for display.
/// A chosen one must pass `weakness` and differ from the current one (`Ok(Err(_))` otherwise, nothing changed).
/// `by_admin`: the user will have to choose their own at the next sign-in. App passwords stay valid; web sessions end.
pub fn user_passwd(
    db: &Db,
    t: &TenantCtx,
    user: &str,
    password: Option<&str>,
    min: usize,
    by_admin: bool,
) -> Result<std::result::Result<String, Weak>> {
    let current = db.user_password_hash(t, user)?;
    let Some(current) = current else {
        // A linked account has no password: `user passwd` is the documented recovery, and it unlinks the identity
        // (audited). The web path (`by_admin = false`) stays refused.
        if !by_admin {
            return Err(Error::Invalid(format!("unknown account in {}: {user}", t.name())));
        }
        let password = match password {
            Some(p) => {
                if let Some(w) = weakness(p, user, t.name(), min) {
                    return Ok(Err(w));
                }
                p.to_owned()
            }
            None => crate::auth::random_hex::<16>()?,
        };
        if !db.user_oidc_unlink_with_password(t, user, &hash(&password)?)? {
            return Err(Error::Invalid(format!("unknown account in {}: {user}", t.name())));
        }
        return Ok(Ok(password));
    };
    let password = match password {
        Some(p) => {
            if let Some(w) = weakness(p, user, t.name(), min) {
                return Ok(Err(w));
            }
            if crate::auth::check_password(&current, p) {
                return Ok(Err(Weak::Reused));
            }
            p.to_owned()
        }
        None => crate::auth::random_hex::<16>()?,
    };
    if !db.user_set_password_hash(t, user, &hash(&password)?, by_admin)? {
        return Err(Error::Invalid(format!("unknown account in {}: {user}", t.name())));
    }
    Ok(Ok(password))
}

/// `beastbox rescan` (§6): reconciles a user's tree after a change made outside the application.
pub fn rescan(t: &TenantCtx, user: &str, path: Option<&str>, readers: usize) -> Result<crate::fs::RescanReport> {
    let u = crate::auth::UserCtx::local_admin(t, user)?;
    let p = path.map(|p| SafePath::new(p.trim_matches('/'))).transpose()?;
    let root = u.root()?;
    root.ensure_layout()?; // a file copy (rclone) does not bring back empty folders: `.trash`, `.beastbox-tmp`
    Ok(root.rescan_with(p.as_ref(), readers)?)
}

/// `beastbox restore`: brings back `path` from `from` (a ZFS snapshot of the user's dataset, or a folder where a
/// backup was restored): at its own place if it no longer exists, otherwise **next to** the current version, as
/// `<path> (restored YYYY-MM-DD)`. Nothing is overwritten, the copy gets new identities. Returns where it went.
pub fn restore(
    t: &TenantCtx,
    user: &str,
    from: &std::path::Path,
    path: &str,
    to: Option<&str>,
) -> Result<(SafePath, crate::fs::CopyReport)> {
    let u = crate::auth::UserCtx::local_admin(t, user)?;
    let p = SafePath::new(path.trim_matches('/'))?;
    let root = u.root()?;
    root.ensure_layout()?;
    let src = crate::fs::Root::open_dir(from).map_err(|e| Error::Invalid(format!("{}: {e}", from.display())))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let day = crate::web::render::date(now);
    let is_file = src.meta(Some(&p)).is_ok_and(|m| m.is_file);
    // Chosen target; or gone: back at its own place (the clients see it reappear); still there: next to it.
    let to = if let Some(t) = to {
        SafePath::new(t.trim_matches('/'))?
    } else if root
        .meta(Some(&p))
        .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        p.clone()
    } else {
        restored_name(&p, is_file, &day)?
    };
    let rep = root.restore_from(&src, &p, &to).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => Error::Invalid(format!("{} already exists", to.as_str())),
        std::io::ErrorKind::NotFound => Error::Invalid(format!("{} not found in {}", p.as_str(), from.display())),
        _ => e.into(),
    })?;
    Ok((to, rep))
}

/// Default name of a restored item: `<path> (restored YYYY-MM-DD)`. A file keeps its extension last
/// ("photo (restored …).jpg"); a folder name, a name without extension and a dot file are kept whole.
fn restored_name(p: &SafePath, is_file: bool, day: &str) -> Result<SafePath> {
    let (stem, ext) = match p.as_str().rsplit_once('.') {
        // A file keeps its extension last, and only a real one: a trailing dot stays in the name (Windows clients
        // refuse a name ending with a dot).
        Some((s, e)) if is_file && !e.contains('/') && !e.is_empty() && !s.is_empty() && !s.ends_with('/') => {
            (s, format!(".{e}"))
        }
        _ => (p.as_str(), String::new()),
    };
    SafePath::new(&format!("{stem} (restored {}){ext}", day.get(..10).unwrap_or(day)))
}

/// `beastbox manifest` (§6): snapshot of `user`'s identities, tags, favorites and trash, in their dataset, before a
/// backup by file copy.
pub fn manifest(t: &TenantCtx, user: &str) -> Result<crate::fs::ManifestReport> {
    let u = crate::auth::UserCtx::local_admin(t, user)?;
    let root = u.root()?;
    root.ensure_layout()?;
    Ok(root.write_manifest()?)
}

/// `beastbox verify` (§6): read-only, reports deviations from the write contract.
pub fn verify(t: &TenantCtx, user: &str, path: Option<&str>) -> Result<crate::fs::VerifyReport> {
    let u = crate::auth::UserCtx::local_admin(t, user)?;
    let p = path.map(|p| SafePath::new(p.trim_matches('/'))).transpose()?;
    Ok(u.root()?.verify(p.as_ref())?)
}

/// `beastbox user enable|disable`: a disabled account can no longer sign in, its sessions end, its devices and public
/// links stop answering; enabling it brings back its devices and links (not its sessions). Its files are untouched.
pub fn user_set_active(db: &Db, t: &TenantCtx, user: &str, active: bool) -> Result<()> {
    if db.user_set_active(t, user, active)? {
        Ok(())
    } else {
        Err(Error::Invalid(format!("unknown account in {}: {user}", t.name())))
    }
}

/// `beastbox user 2fa-reset` (lost phone and recovery codes): two-step verification removed, web sessions ended (a
/// session opened with the old factor does not survive). Devices stay. `Ok(false)`: it was not on.
pub fn user_totp_reset(db: &Db, t: &TenantCtx, user: &str) -> Result<bool> {
    let Some((secret, _)) = db.totp_get(t, user)? else {
        return Err(Error::Invalid(format!(
            "unknown or disabled account in {}: {user}",
            t.name()
        )));
    };
    db.totp_disable(t, user)?;
    db.session_delete_user(t, user)?;
    Ok(secret.is_some())
}

pub fn user_list(db: &Db, t: &TenantCtx) -> Result<Vec<UserRow>> {
    db.user_list(t, 10_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenant::tests::two_tenants;

    #[test]
    fn passwd() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("app.db")).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let (a, b) = (reg.by_name("alpha").unwrap(), reg.by_name("beta").unwrap());
        db.user_add(&a, "alice", &hash("ancien-secret-1").unwrap(), false)
            .unwrap();
        db.user_add(&b, "alice", &hash("ancien-secret-1").unwrap(), false)
            .unwrap();
        let set = |t, p, min| user_passwd(&db, t, "alice", p, min, false).unwrap();
        let must = |t| db.user_must_change(t, "alice").unwrap();
        assert_eq!(must(&a), Some(true)); // created by the administrator
        assert_eq!(set(&a, Some("court"), 12), Err(Weak::Short));
        assert_eq!(set(&a, Some("ancien-secret-1"), 12), Err(Weak::Reused));
        assert_eq!(set(&a, Some("mon-alice-123"), 12), Err(Weak::Name));
        assert_eq!(set(&a, Some("assez-long-1"), 13), Err(Weak::Short)); // the setting is applied
        assert_eq!(must(&a), Some(true)); // a refusal changes nothing
        assert_eq!(set(&a, Some("assez-long-1"), 12).as_deref(), Ok("assez-long-1"));
        assert_eq!((must(&a), must(&b)), (Some(false), Some(true))); // chosen by alice; beta's alice untouched
        let dummy = crate::auth::dummy_hash().unwrap();
        assert!(
            crate::auth::verify_human(&db, &a, "alice", "assez-long-1", &dummy)
                .unwrap()
                .is_some()
        );
        // The other tenant's alice keeps her own password: "assez-long-1" was never hers.
        assert!(
            crate::auth::verify_human(&db, &b, "alice", "assez-long-1", &dummy)
                .unwrap()
                .is_none()
        );
        assert!(user_passwd(&db, &b, "bob", Some("assez-long-1"), 12, true).is_err()); // unknown account
        // Set by the administrator (chosen or generated): to be replaced at the next sign-in.
        assert!(
            user_passwd(&db, &a, "alice", Some("choisi-par-admin"), 12, true)
                .unwrap()
                .is_ok()
        );
        assert_eq!(must(&a), Some(true));
        assert!(user_passwd(&db, &a, "alice", None, 12, true).unwrap().is_ok());
        assert_eq!(must(&a), Some(true));
        user_set_active(&db, &a, "alice", false).unwrap();
        assert_eq!(must(&a), None); // disabled: as unknown
        user_set_active(&db, &a, "alice", true).unwrap();
        assert_eq!(set(&a, None, 12).unwrap().len(), 32); // generated: never refused
        assert_eq!(set(&a, None, 128).unwrap().len(), 32);
    }

    /// Enable/disable: the list shows the state, an unknown account is an error, the other tenant's alice is untouched.
    #[test]
    fn enable_disable() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("app.db")).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let (a, b) = (reg.by_name("alpha").unwrap(), reg.by_name("beta").unwrap());
        db.user_add(&a, "alice", "x", false).unwrap();
        db.user_add(&b, "alice", "x", false).unwrap();
        let active = |t| user_list(&db, t).unwrap().iter().map(|u| u.active).collect::<Vec<_>>();
        user_set_active(&db, &a, "alice", false).unwrap();
        assert_eq!((active(&a), active(&b)), (vec![false], vec![true]));
        assert!(user_set_active(&db, &b, "bob", false).is_err());
        user_set_active(&db, &a, "alice", true).unwrap();
        assert_eq!(active(&a), vec![true]);
    }

    /// Boundaries of the length (at, below, above; the floor wins over a lower setting) and every refusal kind.
    #[test]
    fn weakness_rules() {
        let w = |p: &str, min| weakness(p, "alice", "alpha", min);
        assert_eq!(w("x7#kq2m!vb", 10), None); // 10: at
        assert_eq!(w("x7#kq2m!v", 10), Some(Weak::Short)); // 9: below
        assert_eq!(w("x7#kq2m!v", 5), Some(Weak::Short)); // below the floor whatever the setting
        assert_eq!(w("x7#kq2m!vbz", 12), Some(Weak::Short));
        assert_eq!(w("x7#kq2m!vbzw", 12), None);
        assert_eq!(w("é7#kq2m!vb", 10), None); // characters, not bytes
        assert_eq!(w("x7k2x7k2x7k2", 10), None); // 4 distinct characters: at the limit
        assert_eq!(w("x7kx7kx7kx7k", 10), Some(Weak::Trivial)); // 3: below
        for name in ["xxALICExxxxx", "mon-alpha-2026", "Alice1234567"] {
            assert_eq!(w(name, 10), Some(Weak::Name), "{name}");
        }
        assert_eq!(weakness("ab-x7#kq2m!", "ab", "cd", 10), None); // names under 3 characters are not searched
        for trivial in [
            "aaaaaaaaaaaa",
            "abababababab",
            "abcabcabcabc",
            "1234567890",
            "0987654321",
            "8901234567",
            "abcdefghijkl",
            "AZERTYUIOPQS",
            "qwertyuiopas",
            "poiuytreza",
            "1qaz2wsx3edc",
        ] {
            assert_eq!(w(trivial, 10), Some(Weak::Trivial), "{trivial}");
        }
        for ok in [
            "correct horse battery",
            "azertyuiop!",
            "Tr0ub4dor&3x",
            "nouveau-mot-de-passe",
        ] {
            assert_eq!(w(ok, 10), None, "{ok}");
        }
    }

    /// Every refusal has a French text (they are not literals in a translation call, so the i18n audit does not see them).
    #[test]
    fn weakness_messages_are_translated() {
        for w in [Weak::Short, Weak::Name, Weak::Trivial, Weak::Reused] {
            assert_ne!(crate::i18n::Lang::Fr.t(w.message()), w.message(), "{w:?}");
        }
    }

    /// A step on one of four accounts (alpha/beta × alice/bob) for the model below.
    #[derive(Clone, Debug)]
    enum Step {
        /// The password is set: by the administrator (`true`) or chosen by the user (`false`).
        Set(bool),
        /// A refused choice (too short): changes nothing.
        Refused,
        Disable,
        Enable,
        /// A web session is opened (if the account is active).
        Login,
    }

    fn step() -> impl proptest::strategy::Strategy<Value = (usize, Step)> {
        use proptest::prelude::*;
        let s = prop_oneof![
            any::<bool>().prop_map(Step::Set),
            Just(Step::Refused),
            Just(Step::Disable),
            Just(Step::Enable),
            Just(Step::Login),
        ];
        (0usize..4, s)
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]
        /// Model of the "must change" state: set by the administrator → must change, chosen → not, a refusal or
        /// enabling/disabling changes nothing; any password change ends the account's sessions (not the others'); a
        /// session tells the state; a disabled account has none. Each account evolves alone (other user, other tenant).
        #[test]
        fn must_change_follows_who_set_the_password(steps in proptest::collection::vec(step(), 1..40)) {
            let (reg, _a, _b) = two_tenants();
            let d = tempfile::tempdir().unwrap();
            let db = Db::open(&d.path().join("app.db")).unwrap();
            db.sync_tenants(reg.all()).unwrap();
            let ts = [reg.by_name("alpha").unwrap(), reg.by_name("beta").unwrap()];
            let acc = |i: usize| (&ts[i / 2], ["alice", "bob"][i % 2]);
            // Model: (must_change, active, open sessions).
            let mut m = [(true, true, Vec::<[u8; 32]>::new()), (true, true, vec![]), (true, true, vec![]), (true, true, vec![])];
            for i in 0..4 {
                let (t, u) = acc(i);
                db.user_add(t, u, "h", false).unwrap();
            }
            let mut n = 0u8;
            for (i, s) in steps {
                let (t, u) = acc(i);
                match s {
                    Step::Set(by_admin) => {
                        proptest::prop_assert!(db.user_set_password_hash(t, u, "h", by_admin).unwrap());
                        m[i].0 = by_admin;
                        m[i].2.clear();
                    }
                    Step::Refused => {
                        let r = user_passwd(&db, t, u, Some("court"), 12, false);
                        // A disabled account is unknown to `user_passwd`.
                        let ok = if m[i].1 { r.is_ok_and(|x| x == Err(Weak::Short)) } else { r.is_err() };
                        proptest::prop_assert!(ok);
                    }
                    Step::Disable => {
                        user_set_active(&db, t, u, false).unwrap();
                        m[i].1 = false;
                        m[i].2.clear();
                    }
                    Step::Enable => {
                        user_set_active(&db, t, u, true).unwrap();
                        m[i].1 = true;
                    }
                    Step::Login => {
                        n += 1; // at most 40 steps: each session has its own digest
                        let mut mac = [7u8; 32];
                        mac[0] = n;
                        if m[i].1 {
                            db.session_add(t, u, &mac, 60).unwrap();
                            m[i].2.push(mac);
                        }
                    }
                }
                for (j, (must, active, sessions)) in m.iter().enumerate() {
                    let (t, u) = acc(j);
                    proptest::prop_assert_eq!(db.user_must_change(t, u).unwrap(), active.then_some(*must));
                    for mac in sessions {
                        proptest::prop_assert_eq!(db.session_user(t, mac).unwrap().map(|r| (r.user, r.must_change)), Some((u.to_owned(), *must)));
                    }
                }
            }
        }

        /// Below the length (setting or floor) always refused; a refusal never depends on anything but the arguments;
        /// a password accepted at a given minimum stays accepted at a lower one.
        #[test]
        fn weakness_is_monotonic(p in "\\PC{0,40}", min in 0usize..40) {
            let n = p.chars().count();
            let r = weakness(&p, "alice", "alpha", min);
            if n < min.max(MIN_PASSWORD) {
                proptest::prop_assert_eq!(r, Some(Weak::Short));
            } else {
                proptest::prop_assert_ne!(r, Some(Weak::Short));
            }
            if r.is_none() {
                proptest::prop_assert_eq!(weakness(&p, "alice", "alpha", min.saturating_sub(1)), None);
                proptest::prop_assert!(!p.to_lowercase().contains("alice"));
            }
        }
    }

    #[test]
    fn usernames() {
        for ok in ["alice", "a.b-c_1"] {
            assert!(valid_username(ok));
        }
        for bad in ["", ".trash", "Alice", "a/b", "..", "é", &"a".repeat(65)] {
            assert!(!valid_username(bad), "{bad:?}");
        }
    }

    /// `user oidc-link`: the subject is 1 to 255 visible ASCII characters, the issuer an `https` URL, both checked
    /// before any write; an identity already bound is refused and resolves to its own account only.
    #[test]
    fn oidc_link_checks_subject_and_issuer() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("app.db")).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let a = reg.by_name("alpha").unwrap();
        let h = hash("alice-secret-123").unwrap();
        for u in ["alice", "bob"] {
            db.user_add(&a, u, &h, false).unwrap();
        }
        let iss = "https://auth.example";
        // Subject: 0 refused, 1 and 255 accepted, 256 refused; visible ASCII only.
        assert!(user_oidc_link(&db, &a, "alice", iss, "").is_err());
        assert!(user_oidc_link(&db, &a, "alice", iss, &"s".repeat(256)).is_err());
        for bad in ["a b", "a\tb", "a\u{7}", "é", "a\nb"] {
            assert!(user_oidc_link(&db, &a, "alice", iss, bad).is_err(), "{bad:?}");
        }
        // Issuer: the strict `https` grammar (it is the configured value, compared byte for byte).
        for bad in ["http://auth.example", "auth.example", "", "https://Auth.example"] {
            assert!(user_oidc_link(&db, &a, "alice", bad, "s").is_err(), "{bad:?}");
        }
        // Account name, then the bound itself.
        assert!(user_oidc_link(&db, &a, "nobody", iss, "s").is_err());
        assert!(user_oidc_link(&db, &a, "Alice", iss, "s").is_err());
        assert!(user_oidc_link(&db, &a, "alice", iss, &"s".repeat(255)).is_ok());
        assert_eq!(
            db.user_by_oidc(&a, iss, &"s".repeat(255)).unwrap().as_deref(),
            Some("alice")
        );
        // One byte, and a second account cannot take an identity already bound (the message says why).
        let e = user_oidc_link(&db, &a, "bob", iss, &"s".repeat(255))
            .unwrap_err()
            .to_string();
        assert!(e.contains("already linked"), "{e}");
        assert!(user_oidc_link(&db, &a, "bob", iss, "x").is_ok());
        assert_eq!(db.user_by_oidc(&a, iss, "x").unwrap().as_deref(), Some("bob"));
    }

    /// `user passwd` on a linked account is the recovery procedure: the identity goes and a password comes back. The
    /// web path (`by_admin = false`) refuses, a weak choice is refused without touching the link, and the password
    /// login of the account is refused before and after the link until the recovery.
    #[test]
    fn passwd_unlinks_a_linked_account() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("app.db")).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let a = reg.by_name("alpha").unwrap();
        let iss = "https://auth.example";
        db.user_add_oidc(&a, "alice", false).unwrap();
        let dummy = crate::auth::dummy_hash().unwrap();
        let human = |pw: &str| {
            crate::auth::verify_human(&db, &a, "alice", pw, &dummy)
                .unwrap()
                .is_some()
        };
        // No password: nothing opens the account, before and after linking.
        assert!(!human(""));
        assert!(!human("pw-initial-42"));
        user_oidc_link(&db, &a, "alice", iss, "sub-alice").unwrap();
        assert!(!human("pw-initial-42"));
        // The web path cannot unlink it, and a weak choice changes nothing.
        assert!(user_passwd(&db, &a, "alice", Some("mon-alice-123"), 12, false).is_err());
        assert_eq!(
            user_passwd(&db, &a, "alice", Some("court"), 12, true).unwrap(),
            Err(Weak::Short)
        );
        assert_eq!(db.user_by_oidc(&a, iss, "sub-alice").unwrap().as_deref(), Some("alice"));
        // A generated one: the identity goes, the password works, the user chooses their own at the next sign-in.
        let pw = user_passwd(&db, &a, "alice", None, 12, true).unwrap().unwrap();
        assert_eq!(pw.len(), 32);
        assert_eq!(db.user_by_oidc(&a, iss, "sub-alice").unwrap(), None);
        assert_eq!(db.user_must_change(&a, "alice").unwrap(), Some(true));
        assert!(human(&pw));
        // An account that exists but is neither linked nor has a password stays unknown to `user passwd`.
        db.user_add_oidc(&a, "bob", false).unwrap();
        assert!(user_passwd(&db, &a, "bob", None, 12, true).is_err());
        assert!(user_passwd(&db, &a, "nobody", None, 12, true).is_err());
    }

    #[test]
    fn user_dir_must_be_a_dataset() {
        let (reg, a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("app.db")).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let t = reg.by_name("alpha").unwrap();
        assert!(
            user_add(&db, &t, "alice", true)
                .unwrap_err()
                .to_string()
                .contains("not found")
        );
        std::fs::create_dir(a.path().join("alice")).unwrap();
        assert!(
            user_add(&db, &t, "alice", true)
                .unwrap_err()
                .to_string()
                .contains("not a distinct dataset")
        );
        assert!(user_list(&db, &t).unwrap().is_empty());
    }

    /// `user add --oidc`: the account's dataset is checked exactly like `user add` (nothing is created before it is a
    /// distinct, usable dataset), the name is checked first, and no password is generated.
    #[test]
    fn add_oidc_checks_the_dataset() {
        let (reg, a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("app.db")).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let t = reg.by_name("alpha").unwrap();
        assert!(user_add_oidc(&db, &t, "Alice", false).is_err(), "invalid name accepted");
        let e = user_add_oidc(&db, &t, "alice", false).unwrap_err().to_string();
        assert!(e.contains("not found"), "{e}");
        std::fs::create_dir(a.path().join("alice")).unwrap();
        let e = user_add_oidc(&db, &t, "alice", false).unwrap_err().to_string();
        assert!(e.contains("not a distinct dataset"), "{e}");
        assert!(user_list(&db, &t).unwrap().is_empty());
    }

    /// The default name of a restored item: a file keeps its extension last, a folder name, a name without extension
    /// and a dot file are kept whole. Never the source name itself, so a copy never replaces what it restores.
    #[test]
    fn restored_names() {
        let day = "2026-11-17 09:20";
        let name = |p: &str, is_file| restored_name(&SafePath::new(p).unwrap(), is_file, day).unwrap();
        for (p, is_file, want) in [
            ("Docs/contrat.pdf", true, "Docs/contrat (restored 2026-11-17).pdf"),
            ("v1.2/a.b.txt", true, "v1.2/a.b (restored 2026-11-17).txt"),
            ("Docs.v2/c", true, "Docs.v2/c (restored 2026-11-17)"),
            ("Docs/notes", true, "Docs/notes (restored 2026-11-17)"),
            (".env", true, ".env (restored 2026-11-17)"),
            ("a.", true, "a. (restored 2026-11-17)"),
            ("v1.2", false, "v1.2 (restored 2026-11-17)"),
            ("Docs/contrat.pdf", false, "Docs/contrat.pdf (restored 2026-11-17)"),
        ] {
            assert_eq!(name(p, is_file).as_str(), want, "{p} (file: {is_file})");
        }
        // Bounds of the name the suffix still fits on (255 bytes; " (restored YYYY-MM-DD)" takes 22).
        assert!(restored_name(&SafePath::new(&"a".repeat(233)).unwrap(), true, day).is_ok());
        assert!(restored_name(&SafePath::new(&"a".repeat(234)).unwrap(), true, day).is_err());
    }

    /// Same rule, over any name: the result is a legal path in the same folder, never the source, and space is
    /// never left at the wrong side of the extension.
    #[test]
    fn restored_name_is_legal_and_keeps_the_extension() {
        use proptest::prelude::*;
        use proptest::test_runner::{Config, TestRunner};
        let day = "2026-11-17 09:20";
        let cases = std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(32);
        let strategy = (
            prop::collection::vec(prop::sample::select(vec!['a', 'b', '.', '-']), 1..24),
            any::<bool>(),
        );
        let r = TestRunner::new(Config::with_cases(cases)).run(&strategy, |(chars, is_file)| {
            let raw: String = chars.into_iter().collect();
            let Ok(p) = SafePath::new(&raw) else { return Ok(()) };
            let out = restored_name(&p, is_file, day).unwrap();
            prop_assert!(out.split_parent().0 == p.split_parent().0, "{}", out.as_str());
            prop_assert!(out.as_str().contains(" (restored 2026-11-17)"), "{}", out.as_str());
            prop_assert_ne!(out.as_str(), p.as_str(), "never the source name itself");
            let last = p.as_str().rsplit('/').next().unwrap_or_default();
            if !last.contains('.') {
                let want = format!("{raw} (restored 2026-11-17)");
                prop_assert_eq!(out.as_str(), want.as_str());
            }
            Ok(())
        });
        assert!(r.is_ok(), "{r:?}");
    }
}
