//! The administration CLI as the administrator runs it: the real `beastbox` binary, a real configuration file, two
//! tenants (`alpha`, `beta`); each command is judged by its exit code, what it prints, and what it changed (database,
//! files) — and what it did not change: another user, the other tenant. FreeBSD only (ZFS, xattrs).
//!
//! The binary refuses two tenants on one dataset and a user folder that is not its own dataset, so these tests need
//! real datasets, created once (TESTING.md): `zroot/beastbox-ci` on `/var/tmp/beastbox-ci` (or `BEASTBOX_CI_ROOT`)
//! with `alpha`, `beta` and `alpha/carol`, owned by the user running the tests. Their content is emptied before each
//! test, so the tests take turns (one lock).
#![cfg(target_os = "freebsd")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use beastbox::auth;
use beastbox::config::Config;
use beastbox::db::Db;
use beastbox::tenant::{Registry, TenantCtx};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// A configuration with two tenants on plain folders, and the accounts alice (alpha, beta) and bob (alpha) created
/// through the library with the password `pw-initial-42`, chosen by them (no change required).
struct Bench {
    dir: tempfile::TempDir,
    ci: PathBuf,
    config: PathBuf,
    _turn: std::sync::MutexGuard<'static, ()>,
}

/// The CI datasets are shared: one test at a time.
static TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Empties a dataset's content, keeping the child datasets themselves (their mount points).
fn empty(dir: &std::path::Path, keep: &[&str]) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if keep.contains(&name.as_str()) {
            empty(&p, &[]);
        } else if p.is_dir() {
            std::fs::remove_dir_all(&p).unwrap();
        } else {
            std::fs::remove_file(&p).unwrap();
        }
    }
}

impl Bench {
    fn new() -> Self {
        let turn = TURN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let ci = PathBuf::from(std::env::var("BEASTBOX_CI_ROOT").unwrap_or_else(|_| "/var/tmp/beastbox-ci".into()));
        assert!(
            ci.join("alpha/carol").is_dir() && ci.join("beta").is_dir(),
            "CI datasets missing at {}: see docs/dev/TESTING.md",
            ci.display()
        );
        empty(&ci.join("alpha"), &["carol"]);
        empty(&ci.join("beta"), &[]);
        for d in ["alpha/alice", "alpha/bob", "beta/alice"] {
            std::fs::create_dir_all(ci.join(d)).unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("state")).unwrap();
        let config = dir.path().join("beastbox.toml");
        std::fs::write(
            &config,
            format!(
                "trusted_proxies = [\"127.0.0.1\"]\nstate_dir = \"{}/state\"\nlog_level = \"error\"\n\
                 [[tenant]]\nname = \"alpha\"\nhosts = [\"files.alpha.example\"]\ndata_root = \"{1}/alpha\"\n\
                 [[tenant]]\nname = \"beta\"\nhosts = [\"files.beta.example\"]\ndata_root = \"{1}/beta\"\n",
                dir.path().display(),
                ci.display()
            ),
        )
        .unwrap();
        let b = Bench {
            dir,
            ci,
            config,
            _turn: turn,
        };
        let (db, reg) = b.open();
        let h = auth::hash_password("pw-initial-42").unwrap();
        for (t, u) in [("alpha", "alice"), ("alpha", "bob"), ("beta", "alice")] {
            let t = reg.by_name(t).unwrap();
            db.user_add(&t, u, &h, u == "alice").unwrap();
            db.user_set_password_hash(&t, u, &h, false).unwrap();
        }
        b
    }

    /// The same database and tenant keys as the binary.
    fn open(&self) -> (Db, Registry) {
        let cfg = Config::load(&self.config).unwrap();
        let reg = Registry::build(&cfg.tenants, &cfg.state_dir).unwrap();
        let db = Db::open(&cfg.db_path()).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        (db, reg)
    }

    /// A path under the CI datasets (`alpha/alice/…`), or under the test's own folder for anything else.
    fn path(&self, rel: &str) -> PathBuf {
        if rel.starts_with("alpha") || rel.starts_with("beta") {
            self.ci.join(rel)
        } else {
            self.dir.path().join(rel)
        }
    }

    /// `beastbox -c <config> ARGS`, with `stdin` on standard input: (exit code, standard output, standard error).
    fn run(&self, args: &str, stdin: &str) -> (i32, String, String) {
        let mut c = Command::new(env!("CARGO_BIN_EXE_beastbox"))
            .arg("-c")
            .arg(&self.config)
            .args(args.split_whitespace())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
        let o = c.wait_with_output().unwrap();
        let s = |b: Vec<u8>| String::from_utf8_lossy(&b).into_owned();
        (o.status.code().unwrap_or(-1), s(o.stdout), s(o.stderr))
    }

    /// Adds `[tenant.oidc]` to the `alpha` tenant, with its client secret file: single sign-on configured.
    fn enable_oidc(&self) -> String {
        let issuer = "https://auth.example";
        let secret = self.dir.path().join("alpha-oidc.secret");
        std::fs::write(&secret, "s3cret-value\n").unwrap();
        let text = std::fs::read_to_string(&self.config).unwrap();
        let anchor = format!("data_root = \"{}\"\n", self.ci.join("alpha").display());
        let block = format!(
            "[tenant.oidc]\nissuer = \"{issuer}\"\nclient_id = \"beastbox-alpha\"\nclient_secret_file = \"{}\"\n",
            secret.display()
        );
        std::fs::write(&self.config, text.replacen(&anchor, &format!("{anchor}{block}"), 1)).unwrap();
        issuer.to_owned()
    }

    /// Keep the local password form on the tenant that signs in through its provider (`password_login = true`).
    fn keep_password_login(&self) {
        let text = std::fs::read_to_string(&self.config).unwrap();
        std::fs::write(
            &self.config,
            text.replacen("[tenant.oidc]\n", "[tenant.oidc]\npassword_login = true\n", 1),
        )
        .unwrap();
    }

    /// The human password `pw` opens `user`'s account in `tenant`.
    fn signs_in(&self, tenant: &str, user: &str, pw: &str) -> bool {
        let (db, reg) = self.open();
        let dummy = auth::dummy_hash().unwrap();
        auth::verify_human(&db, &reg.by_name(tenant).unwrap(), user, pw, &dummy)
            .unwrap()
            .is_some()
    }

    fn tenant(&self, name: &str) -> (Db, TenantCtx) {
        let (db, reg) = self.open();
        (db, reg.by_name(name).unwrap())
    }
}

fn list(b: &Bench, tenant: &str) -> String {
    let (code, out, err) = b.run(&format!("user list --tenant {tenant}"), "");
    assert_eq!(code, 0, "{err}");
    out
}

/// Single sign-on: `user add --oidc` needs `[tenant.oidc]` and creates an account with no password; `user oidc-link`
/// binds the provider identity to that one account of that one tenant; `user passwd` is the recovery, which unlinks it.
/// Nothing of the client secret ever reaches standard output or error.
#[test]
fn oidc_add_link_and_recover() {
    let b = Bench::new();
    let issuer = b.enable_oidc();
    // The account exists, without a password: neither the initial one nor an empty one opens it.
    let (code, out, err) = b.run("user add --tenant alpha carol --oidc", "");
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("provider sign-in") && out.contains("oidc-link"), "{out}");
    assert!(!b.signs_in("alpha", "carol", "pw-initial-42"));
    assert!(!b.signs_in("alpha", "carol", ""));
    let (db, t) = b.tenant("alpha");
    assert_eq!(db.user_password_hash(&t, "carol").unwrap(), None);
    assert_eq!(db.user_by_oidc(&t, &issuer, "sub-carol").unwrap(), None);
    // The link: the subject is required, then the identity resolves to that account and to no other tenant.
    let (code, _, err) = b.run("user oidc-link --tenant alpha carol", "");
    assert_eq!(code, 2, "{err}");
    let (code, out, err) = b.run("user oidc-link --tenant alpha carol --subject sub-carol", "");
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("sub-carol"), "{out}");
    let (db, t) = b.tenant("alpha");
    assert_eq!(
        db.user_by_oidc(&t, &issuer, "sub-carol").unwrap().as_deref(),
        Some("carol")
    );
    let (_, other) = b.tenant("beta");
    assert_eq!(db.user_by_oidc(&other, &issuer, "sub-carol").unwrap(), None); // isolated
    assert!(
        db.user_by_oidc(&t, "https://other.example", "sub-carol")
            .unwrap()
            .is_none()
    );
    // A password set on a tenant that signs in through its provider will not open the web login: the CLI says so,
    // and prints nothing of the sort when the local form is kept (`password_login = true`).
    let (code, out, err) = b.run("user passwd --tenant alpha alice", "");
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("will not open the web login"), "{out}");
    b.keep_password_login();
    let (code, out, err) = b.run("user passwd --tenant alpha alice", "");
    assert_eq!(code, 0, "{err}");
    assert!(!out.contains("will not open the web login"), "{out}");
    // An identity is bound once: the same subject on another account of the tenant is refused, the first link stays.
    let (code, _, err) = b.run("user oidc-link --tenant alpha alice --subject sub-carol", "");
    assert_ne!(code, 0, "{err}");
    assert!(err.contains("already linked"), "{err}");
    assert_eq!(
        db.user_by_oidc(&t, &issuer, "sub-carol").unwrap().as_deref(),
        Some("carol")
    );
    assert_eq!(db.user_by_oidc(&t, &issuer, "sub-alice").unwrap(), None);
    // Bounds of the subject, and a tenant without single sign-on.
    for bad in [&"s".repeat(256), "a\tb", "root:x"] {
        let (code, _, _) = b.run(&format!("user oidc-link --tenant alpha carol --subject {bad}"), "");
        assert_ne!(code, 0, "{bad:?}");
    }
    let (code, _, err) = b.run("user add --tenant beta frank --oidc", "");
    assert_ne!(code, 0, "{err}");
    assert!(err.contains("[tenant.oidc]"), "{err}");
    let (code, _, err) = b.run("user oidc-link --tenant beta alice --subject sub-alice", "");
    assert_ne!(code, 0, "{err}");
    // Recovery: `user passwd` unlinks and sets a password the account can sign in with, audited.
    let (code, out, err) = b.run("user passwd --tenant alpha carol", "mon-mot-de-passe-42\n");
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("changed"), "{out}");
    assert!(b.signs_in("alpha", "carol", "mon-mot-de-passe-42"));
    let (db, t) = b.tenant("alpha");
    assert_eq!(db.user_by_oidc(&t, &issuer, "sub-carol").unwrap(), None);
    let actions: Vec<_> = db.audit_list(&t).unwrap().into_iter().map(|r| r.action).collect();
    assert_eq!(actions, ["oidc-link", "oidc-unlink"]);
    // The client secret is never printed.
    for (code, out, err) in [
        b.run("user list --tenant alpha", ""),
        b.run("user oidc-link --tenant alpha alice --subject sub-x", ""),
        b.run("user passwd --tenant alpha alice", ""),
    ] {
        assert!(!out.contains("s3cret") && !err.contains("s3cret"), "{code}: {out}{err}");
    }
}

/// Help, version, and a command line that does not parse: exit 2 with the usage, nothing run.
#[test]
fn usage_and_version() {
    let b = Bench::new();
    let (code, out, _) = b.run("--version", "");
    assert_eq!(
        (code, out.trim()),
        (0, format!("beastbox {}", env!("CARGO_PKG_VERSION")).as_str())
    );
    let (code, out, _) = b.run("--help", "");
    assert!(code == 0 && out.contains("user passwd --tenant T NAME"), "{out}");
    for bad in [
        "frobnicate",
        "user list",
        "user passwd --tenant alpha",
        "user add alice",
        "rescan --readers 9 --tenant alpha",
        "user list --tenant alpha extra",
    ] {
        let (code, _, err) = b.run(bad, "");
        assert!(code == 2 && err.contains("usage: beastbox"), "{bad}: {code} {err}");
    }
}

/// `serve` really serves: it stays up and answers on its address, with the tenant of the host name.
#[test]
fn serve_answers() {
    use std::io::Read;
    let b = Bench::new();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let text = std::fs::read_to_string(&b.config).unwrap();
    std::fs::write(&b.config, format!("listen = \"127.0.0.1:{port}\"\n{text}")).unwrap();
    let mut server = Command::new(env!("CARGO_BIN_EXE_beastbox"))
        .arg("-c")
        .arg(&b.config)
        .arg("serve")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut answer = String::new();
    for _ in 0..100 {
        if let Ok(mut c) = std::net::TcpStream::connect(("127.0.0.1", port)) {
            c.write_all(b"GET /status.php HTTP/1.1\r\nHost: files.alpha.example\r\nConnection: close\r\n\r\n")
                .unwrap();
            c.read_to_string(&mut answer).unwrap();
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let still_up = server.try_wait().unwrap().is_none();
    // SIGTERM (service stop): the server finishes by itself, with success.
    let term = Command::new("kill")
        .args(["-TERM", &server.id().to_string()])
        .status()
        .unwrap();
    let mut code = None;
    for _ in 0..150 {
        code = server.try_wait().unwrap();
        if code.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if code.is_none() {
        server.kill().unwrap();
        server.wait().unwrap();
    }
    assert!(
        still_up && answer.contains("200 OK") && answer.contains("\"installed\":true"),
        "{answer}"
    );
    assert!(term.success() && code.is_some_and(|c| c.success()), "{code:?}");
}

/// `check-config`: a good file passes; a missing file, a refused setting and a missing data root fail with exit 1 and
/// a message naming the problem; an unknown tenant is refused by every command.
#[test]
fn check_config_and_unknown_tenant() {
    let b = Bench::new();
    assert_eq!(b.run("check-config", "").0, 0);
    let (code, _, err) = b.run("user list --tenant gamma", "");
    assert!(code == 1 && err.contains("gamma"), "{err}");
    let missing = Command::new(env!("CARGO_BIN_EXE_beastbox"))
        .args(["-c", "/nonexistent/b.toml", "check-config"])
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("/nonexistent/b.toml"));
    let text = std::fs::read_to_string(&b.config).unwrap();
    std::fs::write(&b.config, format!("min_password = 9\n{text}")).unwrap();
    let (code, _, err) = b.run("check-config", "");
    assert!(code == 1 && err.contains("min_password"), "{err}");
    std::fs::write(&b.config, text.replace("/alpha\"", "/nowhere\"")).unwrap();
    let (code, _, err) = b.run("check-config", "");
    assert!(code == 1 && err.contains("nowhere"), "{err}");
}

/// `user add` refusals: a hostile name, a folder that is not a distinct dataset, no folder at all; nothing is added.
#[test]
fn user_add_refusals() {
    let b = Bench::new();
    std::fs::create_dir(b.path("alpha/erin")).unwrap(); // a plain folder
    for (args, msg) in [
        ("user add --tenant alpha Bad.Name", "invalid user name"),
        ("user add --tenant alpha ../x", "invalid user name"),
        ("user add --tenant alpha erin", "not a distinct dataset"),
        ("user add --tenant alpha dave", "create the user's ZFS dataset first"),
    ] {
        let (code, out, err) = b.run(args, "");
        assert!(
            code == 1 && err.contains(msg) && !out.contains("Password"),
            "{args}: {code} {err}"
        );
    }
    assert_eq!(list(&b, "alpha").lines().count(), 2);
}

/// `user add` on a real ZFS dataset: the password is printed once, works, must be replaced at the first sign-in; the
/// folder gets its layout; the same name twice is refused; the other tenant has no carol.
#[test]
fn user_add_on_a_dataset() {
    let b = Bench::new();
    let (code, out, err) = b.run("user add --tenant alpha carol", "");
    assert_eq!(code, 0, "{err}");
    let pw = out.trim().rsplit(' ').next().unwrap().to_owned();
    assert!(pw.len() == 32 && pw.bytes().all(|c| c.is_ascii_hexdigit()), "{out}");
    assert!(b.signs_in("alpha", "carol", &pw));
    let (db, t) = b.tenant("alpha");
    assert_eq!(db.user_must_change(&t, "carol").unwrap(), Some(true));
    assert!(b.path("alpha/carol/.trash").is_dir());
    let (code, _, err) = b.run("user add --tenant alpha carol", "");
    assert!(code == 1 && err.contains("already exists"), "{err}");
    assert!(!list(&b, "beta").contains("carol"));
}

/// `user list`: name, role, state and two-step verification, tab-separated, sorted; one tenant at a time.
#[test]
fn user_list_columns() {
    let b = Bench::new();
    assert_eq!(list(&b, "alpha"), "alice\tadmin\tactive\t-\nbob\tuser\tactive\t-\n");
    assert_eq!(list(&b, "beta"), "alice\tadmin\tactive\t-\n");
    let (db, t) = b.tenant("alpha");
    let s = [7u8; auth::totp::SECRET_LEN];
    let now = auth::totp::now();
    let code = format!("{:06}", auth::totp::hotp(&s, auth::totp::step(now)));
    auth::totp_enable(&db, &t, "bob", &s, &code, now).unwrap().unwrap();
    db.user_set_active(&t, "alice", false).unwrap();
    assert_eq!(list(&b, "alpha"), "alice\tadmin\tdisabled\t-\nbob\tuser\tactive\t2fa\n");
}

/// `user passwd`: an empty line generates a password (printed once); a chosen one is checked by the rules (the reason
/// is printed, nothing changes); either way the user must choose their own at the next sign-in; an unknown account
/// fails; bob and the other tenant's alice keep their password.
#[test]
fn user_passwd() {
    let b = Bench::new();
    let (code, out, err) = b.run("user passwd --tenant alpha alice", "\n");
    assert_eq!(code, 0, "{err}");
    let generated = out.trim().rsplit(' ').next().unwrap().to_owned();
    assert!(out.contains("shown only once") && generated.len() == 32, "{out}");
    assert!(b.signs_in("alpha", "alice", &generated) && !b.signs_in("alpha", "alice", "pw-initial-42"));
    for (weak, why) in [
        ("court", "too short"),
        ("azertyuiopqs", "too easy"),
        ("alice-au-soleil", "account or tenant name"),
        (generated.as_str(), "differ from the current"),
    ] {
        let (code, _, err) = b.run("user passwd --tenant alpha alice", &format!("{weak}\n"));
        assert!(code == 1 && err.contains(why), "{weak}: {err}");
        assert!(b.signs_in("alpha", "alice", &generated), "{weak} changed something");
    }
    let (code, out, _) = b.run("user passwd --tenant alpha alice", "choisi-par-l-admin\n");
    assert!(code == 0 && out.contains("changed") && !out.contains("choisi"), "{out}");
    assert!(b.signs_in("alpha", "alice", "choisi-par-l-admin"));
    let (db, t) = b.tenant("alpha");
    assert_eq!(db.user_must_change(&t, "alice").unwrap(), Some(true));
    // A line ending in CRLF (a password pasted from Windows): the CR is not part of it.
    assert_eq!(b.run("user passwd --tenant alpha alice", "autre-choix-ok\r\n").0, 0);
    assert!(b.signs_in("alpha", "alice", "autre-choix-ok"));
    let (code, _, err) = b.run("user passwd --tenant alpha nobody", "\n");
    assert!(code == 1 && err.contains("nobody"), "{err}");
    assert!(b.signs_in("alpha", "bob", "pw-initial-42") && b.signs_in("beta", "alice", "pw-initial-42"));
}

/// `user disable` / `enable`: the account stops signing in and its sessions end; enabled again it signs in; an
/// unknown account fails; the other tenant's alice is untouched.
#[test]
fn user_disable_enable() {
    let b = Bench::new();
    let (db, t) = b.tenant("alpha");
    db.session_add(&t, "alice", &[1; 32], 60).unwrap();
    let (code, out, _) = b.run("user disable --tenant alpha alice", "");
    assert!(code == 0 && out.contains("disabled"), "{out}");
    assert!(!b.signs_in("alpha", "alice", "pw-initial-42"));
    assert!(b.tenant("alpha").0.session_user(&t, &[1; 32]).unwrap().is_none());
    assert!(b.signs_in("beta", "alice", "pw-initial-42") && b.signs_in("alpha", "bob", "pw-initial-42"));
    let (code, out, _) = b.run("user enable --tenant alpha alice", "");
    assert!(code == 0 && out.contains("enabled"), "{out}");
    assert!(b.signs_in("alpha", "alice", "pw-initial-42"));
    for args in ["user disable --tenant alpha nobody", "user enable --tenant beta bob"] {
        assert_eq!(b.run(args, "").0, 1, "{args}");
    }
}

/// `user 2fa-reset`: two-step verification removed and sessions ended; run again, it says there was none; the other
/// tenant's alice keeps hers; an unknown account fails.
#[test]
fn user_2fa_reset() {
    let b = Bench::new();
    let s = [7u8; auth::totp::SECRET_LEN];
    let now = auth::totp::now();
    let code = format!("{:06}", auth::totp::hotp(&s, auth::totp::step(now)));
    for tenant in ["alpha", "beta"] {
        let (db, t) = b.tenant(tenant);
        auth::totp_enable(&db, &t, "alice", &s, &code, now).unwrap().unwrap();
    }
    let (db, t) = b.tenant("alpha");
    db.session_add(&t, "alice", &[2; 32], 60).unwrap();
    let (code, out, _) = b.run("user 2fa-reset --tenant alpha alice", "");
    assert!(code == 0 && out.contains("removed"), "{out}");
    let (db, _) = b.tenant("alpha");
    assert_eq!(db.totp_get(&t, "alice").unwrap(), Some((None, 0)));
    assert!(db.session_user(&t, &[2; 32]).unwrap().is_none());
    let (code, out, _) = b.run("user 2fa-reset --tenant alpha alice", "");
    assert!(code == 0 && out.contains("had no two-step verification"), "{out}");
    let (dbb, tb) = b.tenant("beta");
    assert!(dbb.totp_get(&tb, "alice").unwrap().unwrap().0.is_some());
    assert_eq!(b.run("user 2fa-reset --tenant alpha nobody", "").0, 1);
}

/// `verify` and `rescan`: a file put in a user's folder outside the application is reported (exit 1, for backup
/// scripts); `rescan --user` reconciles that user only; `verify` is then clean (exit 0) for them, still not for bob.
#[test]
fn verify_and_rescan() {
    let b = Bench::new();
    for t in ["alpha", "beta"] {
        assert_eq!(b.run(&format!("rescan --tenant {t}"), "").0, 0); // every user's layout and identities
    }
    let (code, _, _) = b.run("verify --tenant alpha", "");
    assert_eq!(code, 0);
    std::fs::write(b.path("alpha/alice/ssh.txt"), b"added over SSH").unwrap();
    std::fs::write(b.path("alpha/bob/scp.txt"), b"added with scp").unwrap();
    let (code, out, err) = b.run("verify --tenant alpha --user alice", "");
    assert!(
        code == 1 && out.contains("without identity") && out.contains("ssh.txt") && err.contains("rescan"),
        "{out}"
    );
    let (code, out, _) = b.run("rescan --tenant alpha --user alice", "");
    assert!(code == 0 && out.contains("1 identities assigned"), "{out}");
    assert_eq!(b.run("verify --tenant alpha --user alice", "").0, 0);
    let (code, out, _) = b.run("verify --tenant alpha", "");
    assert!(
        code == 1 && out.contains("scp.txt") && !out.contains("ssh.txt"),
        "{out}"
    );
    assert_eq!(b.run("verify --tenant beta", "").0, 0); // the other tenant saw nothing
    assert_eq!(b.run("verify --tenant alpha --user nobody", "").0, 1);
}

/// `manifest` then `restore`: the manifest lands in each user's dataset; a file brought back from a "snapshot" goes to
/// its place when gone, next to it otherwise (never overwritten); a path outside the snapshot fails.
#[test]
fn manifest_and_restore() {
    let b = Bench::new();
    std::fs::write(b.path("alpha/alice/contrat.pdf"), b"version actuelle").unwrap();
    assert_eq!(b.run("rescan --tenant alpha", "").0, 0);
    let (code, out, _) = b.run("manifest --tenant alpha", "");
    assert!(
        code == 0 && out.contains("alice: manifest written") && out.contains("bob: manifest written"),
        "{out}"
    );
    assert!(b.path("alpha/alice/.beastbox-manifest").is_file() && b.path("alpha/bob/.beastbox-manifest").is_file());
    let snap = b.path("snapshot");
    std::fs::create_dir_all(snap.join("Docs")).unwrap();
    std::fs::write(snap.join("contrat.pdf"), b"version d'hier").unwrap();
    std::fs::write(snap.join("Docs/note.txt"), b"note").unwrap();
    let from = snap.display().to_string();
    let (code, out, err) = b.run(
        &format!("restore --tenant alpha --user alice --from {from} --path Docs/note.txt"),
        "",
    );
    assert!(code == 0 && out.contains("restored as Docs/note.txt"), "{out} {err}");
    assert_eq!(std::fs::read(b.path("alpha/alice/Docs/note.txt")).unwrap(), b"note");
    let (code, out, _) = b.run(
        &format!("restore --tenant alpha --user alice --from {from} --path contrat.pdf"),
        "",
    );
    assert!(code == 0 && out.contains("restored"), "{out}");
    assert_eq!(
        std::fs::read(b.path("alpha/alice/contrat.pdf")).unwrap(),
        b"version actuelle"
    ); // never overwritten
    let copies: Vec<String> = std::fs::read_dir(b.path("alpha/alice"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("contrat (restored"))
        .collect();
    assert_eq!(copies.len(), 1, "{copies:?}");
    assert_eq!(
        std::fs::read(b.path(&format!("alpha/alice/{}", copies[0]))).unwrap(),
        b"version d'hier"
    );
    for path in ["../etc/passwd", "absent.txt"] {
        let (code, _, _) = b.run(
            &format!("restore --tenant alpha --user alice --from {from} --path {path}"),
            "",
        );
        assert_eq!(code, 1, "{path}");
    }
    assert!(!b.path("alpha/bob/Docs").exists()); // bob untouched
    assert_eq!(
        b.run("verify --tenant alpha --user alice", "").0,
        0,
        "the restored copies have their identity"
    );
}
