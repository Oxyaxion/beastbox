use beastbox::config::Config;
use beastbox::db::Db;
use beastbox::fs::SafePath;
use beastbox::tenant::Registry;
use beastbox::{admin, fs, http};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

const DEFAULT_CONFIG: &str = "/usr/local/etc/beastbox.toml";

const USAGE: &str = "usage: beastbox [-c FILE] <command>

commands:
  serve                                     runs the server
  check-config                              checks the configuration and the data roots, then exits
  user add --tenant T NAME [--admin] [--oidc]
                                            adds an account without a password; its dataset <data_root>/NAME must
                                            already exist; prints its activation link (single use, 24 hours): the
                                            person chooses a password there, and binds a phone where the tenant
                                            requires it. --oidc: the account signs in through the provider
                                            ([tenant.oidc] required)
  user oidc-link --tenant T NAME --subject S
                                            binds the provider identity S (the `sub` given by the provider) to
                                            the account; the issuer is the tenant's configured one
  user list --tenant T                      lists the accounts
  user disable --tenant T NAME              no sign-in, sessions ended, devices and public links blocked; files kept
  user enable --tenant T NAME               reverses it: devices and links answer again (sessions do not come back)
  user 2fa-reset --tenant T NAME            removes two-step verification (lost phone and recovery codes) and
                                            ends the web sessions; where the tenant requires it, prints an
                                            activation link to bind the new phone (with the account's password)
  user passwd --tenant T NAME               removes the password (and a provider identity), ends the web sessions,
                                            prints an activation link to choose a new one; devices stay
  verify --tenant T [--user U] [--path P]   read-only: files added or changed outside the application, duplicates
                                            (exit code 1 if there are discrepancies)
  rescan --tenant T [--user U] [--path P]   after a change outside the application (SSH, restore…):
                                            missing identities (recovered from the manifest if there is one) and
                                            ETags of the subtree and its ancestors
                                            --readers N: files read at once to prove restored
                                            contents (1 to 8, default 8)
  restore --tenant T --user U --from DIR --path P [--to Q]
                                            brings P back from DIR (snapshot, restored backup) to Q; by
                                            default at its place if gone, else as \"P (restored DATE)\"
  manifest --tenant T [--user U]            before a backup by file copy (rclone, rsync without -X):
                                            writes into the dataset a snapshot of identities, tags, favorites and trash

options:
  -c, --config FILE      configuration (default: /usr/local/etc/beastbox.toml)
  -h, --help             this help
  -V, --version          version";

struct Cli {
    config: PathBuf,
    cmd: Cmd,
}

#[derive(Debug, PartialEq)]
enum Cmd {
    Serve,
    CheckConfig,
    User {
        cmd: UserCmd,
    },
    Verify {
        tenant: String,
        user: Option<String>,
        path: Option<String>,
    },
    Rescan {
        tenant: String,
        user: Option<String>,
        path: Option<String>,
        readers: usize,
    },
    Manifest {
        tenant: String,
        user: Option<String>,
    },
    Restore {
        tenant: String,
        user: String,
        from: PathBuf,
        path: String,
        to: Option<String>,
    },
}

#[derive(Debug, PartialEq)]
enum UserCmd {
    Add {
        tenant: String,
        name: String,
        admin: bool,
        oidc: bool,
    },
    List {
        tenant: String,
    },
    Passwd {
        tenant: String,
        name: String,
    },
    SetActive {
        tenant: String,
        name: String,
        active: bool,
    },
    TotpReset {
        tenant: String,
        name: String,
    },
    OidcLink {
        tenant: String,
        name: String,
        subject: String,
    },
}

#[derive(Debug, PartialEq)]
enum Parsed {
    Run(PathBuf, Cmd),
    Help,
    Version,
}

/// Command-line parsing (local CLI: deliberately minimal, no dependency).
fn parse(args: impl IntoIterator<Item = String>) -> Result<Parsed, String> {
    let mut config = PathBuf::from(DEFAULT_CONFIG);
    let (mut tenant, mut user, mut path, mut from, mut to, mut readers, mut admin, mut subject) =
        (None, None, None, None, None, None, false, None);
    let mut oidc = false;
    let mut pos: Vec<String> = Vec::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        let mut value = |slot: &mut Option<String>, name: &str| -> Result<(), String> {
            let v = it.next().ok_or_else(|| format!("{name} expects a value"))?;
            if slot.replace(v).is_some() {
                return Err(format!("{name} given twice"));
            }
            Ok(())
        };
        match a.as_str() {
            "-h" | "--help" => return Ok(Parsed::Help),
            "-V" | "--version" => return Ok(Parsed::Version),
            "-c" | "--config" => {
                let mut c = None;
                value(&mut c, "--config")?;
                config = c.map(PathBuf::from).unwrap_or(config);
            }
            "--tenant" => value(&mut tenant, "--tenant")?,
            "--user" => value(&mut user, "--user")?,
            "--path" => value(&mut path, "--path")?,
            "--from" => value(&mut from, "--from")?,
            "--to" => value(&mut to, "--to")?,
            "--readers" => value(&mut readers, "--readers")?,
            "--admin" => admin = true,
            "--oidc" => oidc = true,
            "--subject" => value(&mut subject, "--subject")?,
            o if o.starts_with('-') => return Err(format!("option inconnue : {o}")),
            _ => pos.push(a),
        }
    }
    let need = |t: Option<String>| t.ok_or_else(|| "--tenant is required".to_owned());
    let pos: Vec<&str> = pos.iter().map(String::as_str).collect();
    // An option that does not apply to the command is an error (no option silently ignored).
    let only = |ok: bool| {
        if ok {
            Ok(())
        } else {
            Err("unexpected option for this command".to_owned())
        }
    };
    if (from.is_some() || to.is_some()) && pos.as_slice() != ["restore"]
        || readers.is_some() && pos.as_slice() != ["rescan"]
        || (oidc || subject.is_some()) && !matches!(pos.as_slice(), ["user", "add", _] | ["user", "oidc-link", _])
    {
        return Err("unexpected option for this command".to_owned());
    }
    let cmd = match pos.as_slice() {
        ["serve"] => only(tenant.is_none() && user.is_none() && path.is_none() && !admin).map(|()| Cmd::Serve)?,
        ["check-config"] => {
            only(tenant.is_none() && user.is_none() && path.is_none() && !admin).map(|()| Cmd::CheckConfig)?
        }
        ["user", "add", name] => {
            only(user.is_none() && path.is_none() && subject.is_none())?;
            Cmd::User {
                cmd: UserCmd::Add {
                    tenant: need(tenant)?,
                    name: (*name).to_owned(),
                    admin,
                    oidc,
                },
            }
        }
        ["user", "oidc-link", name] => {
            only(user.is_none() && path.is_none() && !admin && !oidc)?;
            Cmd::User {
                cmd: UserCmd::OidcLink {
                    tenant: need(tenant)?,
                    name: (*name).to_owned(),
                    subject: subject.ok_or_else(|| "--subject is required".to_owned())?,
                },
            }
        }
        ["user", "list"] => {
            only(user.is_none() && path.is_none() && !admin)?;
            Cmd::User {
                cmd: UserCmd::List { tenant: need(tenant)? },
            }
        }
        ["user", verb @ ("enable" | "disable"), name] => {
            only(user.is_none() && path.is_none() && !admin)?;
            Cmd::User {
                cmd: UserCmd::SetActive {
                    tenant: need(tenant)?,
                    name: (*name).to_owned(),
                    active: *verb == "enable",
                },
            }
        }
        ["user", "2fa-reset", name] => {
            only(user.is_none() && path.is_none() && !admin)?;
            Cmd::User {
                cmd: UserCmd::TotpReset {
                    tenant: need(tenant)?,
                    name: (*name).to_owned(),
                },
            }
        }
        ["user", "passwd", name] => {
            only(user.is_none() && path.is_none() && !admin)?;
            Cmd::User {
                cmd: UserCmd::Passwd {
                    tenant: need(tenant)?,
                    name: (*name).to_owned(),
                },
            }
        }
        ["verify"] => {
            only(!admin)?;
            Cmd::Verify {
                tenant: need(tenant)?,
                user,
                path,
            }
        }
        ["rescan"] => {
            only(!admin)?;
            Cmd::Rescan {
                tenant: need(tenant)?,
                user,
                path,
                readers: match readers {
                    None => beastbox::fs::RESCAN_READERS,
                    Some(r) => r
                        .parse()
                        .ok()
                        .filter(|n| (1..=beastbox::fs::RESCAN_READERS).contains(n))
                        .ok_or_else(|| {
                            format!("--readers expects a number from 1 to {}", beastbox::fs::RESCAN_READERS)
                        })?,
                },
            }
        }
        ["manifest"] => {
            only(path.is_none() && !admin)?;
            Cmd::Manifest {
                tenant: need(tenant)?,
                user,
            }
        }
        ["restore"] => {
            only(!admin)?;
            Cmd::Restore {
                tenant: need(tenant)?,
                user: user.ok_or("--user is required")?,
                from: from.map(PathBuf::from).ok_or("--from is required")?,
                path: path.ok_or("--path is required")?,
                to,
            }
        }
        [] => return Err("commande manquante".into()),
        other => return Err(format!("commande inconnue : {}", other.join(" "))),
    };
    Ok(Parsed::Run(config, cmd))
}

fn main() -> ExitCode {
    fs::set_umask();
    fs::init_timezone();
    let cli = match parse(std::env::args().skip(1)) {
        Ok(Parsed::Run(config, cmd)) => Cli { config, cmd },
        Ok(Parsed::Help) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Parsed::Version) => {
            println!("beastbox {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("beastbox : {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("beastbox : {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> beastbox::Result<()> {
    let cfg = Config::load(&cli.config)?;
    let level: tracing::Level = cfg
        .log_level
        .parse()
        .map_err(|_| beastbox::Error::Config("log_level invalide".into()))?;
    tracing_subscriber::fmt().with_max_level(level).with_ansi(false).init();
    let registry = Registry::build(&cfg.tenants, &cfg.state_dir)?;
    let tenant = |name: &str| {
        registry
            .by_name(name)
            .ok_or_else(|| beastbox::Error::Invalid(format!("tenant inconnu : {name}")))
    };
    match cli.cmd {
        Cmd::CheckConfig => {
            println!("configuration valide : {} tenant(s)", registry.all().len());
            Ok(())
        }
        Cmd::User {
            cmd:
                UserCmd::Add {
                    tenant: t,
                    name,
                    admin: is_admin,
                    oidc,
                },
        } => {
            let db = Db::open(&cfg.db_path())?;
            db.sync_tenants(registry.all())?;
            let tc = tenant(&t)?;
            if oidc {
                let issuer = oidc_issuer(&cfg, &t)?;
                admin::user_add_oidc(&db, &tc, &name, is_admin)?;
                println!(
                    "account {name} created in {t} for provider sign-in (issuer {issuer}). Link it with: \
                     beastbox user oidc-link --tenant {t} {name} --subject <sub>"
                );
                return Ok(());
            }
            // The link's address first: nothing is created when it cannot be given.
            let base = cfg.public_base(&t)?;
            admin::user_add(&db, &tc, &name, is_admin)?;
            println!("account {name} created in {t}, without a password.");
            print_link(&db, &tc, &name, &base)?;
            warn_unusable_password(&cfg, &t);
            Ok(())
        }
        Cmd::User {
            cmd:
                UserCmd::OidcLink {
                    tenant: t,
                    name,
                    subject,
                },
        } => {
            let db = Db::open(&cfg.db_path())?;
            db.sync_tenants(registry.all())?;
            let issuer = oidc_issuer(&cfg, &t)?;
            admin::user_oidc_link(&db, &tenant(&t)?, &name, &issuer, &subject)?;
            println!("account {name} in {t} now signs in with the provider identity {subject}");
            Ok(())
        }
        Cmd::User {
            cmd: UserCmd::Passwd { tenant: t, name },
        } => {
            let db = Db::open(&cfg.db_path())?;
            let tc = tenant(&t)?;
            let base = cfg.public_base(&t)?;
            admin::user_reset(&db, &tc, &name)?;
            println!("password of {name} in {t} removed; sessions ended.");
            print_link(&db, &tc, &name, &base)?;
            warn_unusable_password(&cfg, &t);
            Ok(())
        }
        Cmd::User {
            cmd:
                UserCmd::SetActive {
                    tenant: t,
                    name,
                    active,
                },
        } => {
            let db = Db::open(&cfg.db_path())?;
            admin::user_set_active(&db, &tenant(&t)?, &name, active)?;
            println!("account {name} in {t} {}", if active { "enabled" } else { "disabled" });
            Ok(())
        }
        Cmd::User {
            cmd: UserCmd::TotpReset { tenant: t, name },
        } => {
            let db = Db::open(&cfg.db_path())?;
            let tc = tenant(&t)?;
            // Where it is required, the new phone is bound only through an activation link: its address first.
            let required = cfg
                .tenants
                .iter()
                .any(|c| c.name == t && c.two_factor == beastbox::config::TwoFactor::Required);
            let base = if required { Some(cfg.public_base(&t)?) } else { None };
            if admin::user_totp_reset(&db, &tc, &name)? {
                println!("two-step verification of {name} in {t} removed; sessions ended");
            } else {
                println!("{name} in {t} had no two-step verification; sessions ended");
            }
            if let Some(base) = base {
                print_link(&db, &tc, &name, &base)?;
            }
            Ok(())
        }
        Cmd::User {
            cmd: UserCmd::List { tenant: t },
        } => {
            let db = Db::open(&cfg.db_path())?;
            for u in admin::user_list(&db, &tenant(&t)?)? {
                println!(
                    "{}\t{}\t{}\t{}",
                    u.user_id,
                    u.role,
                    if u.active { "active" } else { "disabled" },
                    if u.totp { "2fa" } else { "-" }
                );
            }
            Ok(())
        }
        Cmd::Verify { tenant: t, user, path } => {
            let tc = tenant(&t)?;
            let users = match user {
                Some(u) => vec![u],
                None => admin::user_list(&Db::open(&cfg.db_path())?, &tc)?
                    .into_iter()
                    .map(|u| u.user_id)
                    .collect(),
            };
            let mut clean = true;
            for u in users {
                let r = admin::verify(&tc, &u, path.as_deref())?;
                println!("{u}: {} files, {} folders", r.files, r.dirs);
                for (label, list) in [
                    ("without identity (added outside the application)", &r.missing_id),
                    ("duplicate identity", &r.duplicates),
                    ("changed outside the application", &r.modified),
                ] {
                    for p in list {
                        clean = false;
                        println!("  {label} : {p}");
                    }
                }
                if r.truncated {
                    println!("  … lists truncated to {} entries", beastbox::fs::VERIFY_MAX);
                }
            }
            // Non-zero exit code: a backup or restore script must be able to detect it.
            if clean {
                Ok(())
            } else {
                Err(beastbox::Error::Invalid(
                    "discrepancies found: run `beastbox rescan` to reconcile them".into(),
                ))
            }
        }
        Cmd::Rescan {
            tenant: t,
            user,
            path,
            readers,
        } => {
            let tc = tenant(&t)?;
            let users = match user {
                Some(u) => vec![u],
                None => admin::user_list(&Db::open(&cfg.db_path())?, &tc)?
                    .into_iter()
                    .map(|u| u.user_id)
                    .collect(),
            };
            for u in users {
                let r = admin::rescan(&tc, &u, path.as_deref(), readers)?;
                println!(
                    "{u}: {} files, {} folders, {} identities recovered from the manifest ({} with the same content \
                     and ETag, {} with another content, {} trash slots, {} unreadable lines), {} identities assigned, \
                     {} duplicates reassigned, {} names skipped",
                    r.files,
                    r.dirs,
                    r.manifest.ids,
                    r.manifest.etags_kept,
                    r.manifest.content_changed,
                    r.manifest.trash_slots,
                    r.manifest.bad_lines,
                    r.ids_assigned,
                    r.duplicates,
                    r.skipped
                );
            }
            Ok(())
        }
        Cmd::Manifest { tenant: t, user } => {
            let tc = tenant(&t)?;
            let users = match user {
                Some(u) => vec![u],
                None => admin::user_list(&Db::open(&cfg.db_path())?, &tc)?
                    .into_iter()
                    .map(|u| u.user_id)
                    .collect(),
            };
            for u in users {
                let started = std::time::Instant::now();
                let r = admin::manifest(&tc, &u)?;
                println!(
                    "{u}: manifest written ({} files, {} folders, {} items in the trash) in {:.1} s",
                    r.files,
                    r.dirs,
                    r.trashed,
                    started.elapsed().as_secs_f64()
                );
            }
            Ok(())
        }
        Cmd::Restore {
            tenant: t,
            user,
            from,
            path,
            to,
        } => {
            let (to, r) = admin::restore(&tenant(&t)?, &user, &from, &path, to.as_deref())?;
            println!("{}", restore_report(&user, &path, &to, &r));
            Ok(())
        }
        Cmd::Serve => serve(&cfg, registry),
    }
}

/// A password generated on a tenant that signs in through its provider does not open the web login: say so rather
/// than let the administrator write it down for nothing.
/// A new activation link for `name`, printed once with its address and its rules.
fn print_link(db: &Db, t: &beastbox::tenant::TenantCtx, name: &str, base: &str) -> beastbox::Result<()> {
    let token = beastbox::auth::activation_issue(db, t, name, beastbox::db::now_secs())?;
    println!("activation link (single use, valid 24 hours; send it to {name} only): {base}/activate/{token}");
    Ok(())
}

fn warn_unusable_password(cfg: &Config, tenant: &str) {
    let closed = cfg
        .tenants
        .iter()
        .find(|t| t.name == tenant)
        .and_then(|t| t.oidc.as_ref())
        .is_some_and(|o| !o.password_login);
    if closed {
        println!(
            "note: tenant {tenant} signs in through its provider (password_login = false): a password chosen from \
             this link will not open the web login. Set password_login = true in [tenant.oidc] to use it."
        );
    }
}

/// The issuer of a tenant that has `[tenant.oidc]`: the only value an identity may be linked with.
fn oidc_issuer(cfg: &Config, tenant: &str) -> beastbox::Result<String> {
    cfg.tenants
        .iter()
        .find(|t| t.name == tenant)
        .and_then(|t| t.oidc.as_ref())
        .map(|o| o.issuer.clone())
        .ok_or_else(|| {
            beastbox::Error::Invalid(format!(
                "tenant {tenant} has no [tenant.oidc]: no single sign-on to link"
            ))
        })
}

/// What `restore` prints: where the copy went, and the items passed over only when there are some.
fn restore_report(user: &str, path: &str, to: &SafePath, r: &fs::CopyReport) -> String {
    let mut s = format!(
        "{user}: {path} restored as {} ({} files, {} folders)",
        to.as_str(),
        r.files,
        r.dirs
    );
    if r.skipped > 0 {
        s.push_str(&format!(
            "\n  {} items of the source passed over (link, special file, name not allowed)",
            r.skipped
        ));
    }
    s
}

fn serve(cfg: &Config, registry: Registry) -> beastbox::Result<()> {
    let db = Db::open(&cfg.db_path())?;
    db.sync_tenants(registry.all())?;
    // §0.2: cleanup of temporaries from interrupted writes, without touching user files.
    for t in registry.all() {
        for u in db.user_list(t, 10_000)? {
            let cleaned = SafePath::new(&u.user_id)
                .map_err(|e| std::io::Error::other(e.to_string()))
                .and_then(|p| t.data_root().open_subdir(&p))
                .and_then(|root| root.ensure_layout().and_then(|()| root.clean_tmp()));
            match cleaned {
                Ok(0) => {}
                Ok(n) => tracing::info!(tenant = t.name(), user = u.user_id, n, "orphan temporaries removed"),
                Err(e) => tracing::error!(
                    tenant = t.name(),
                    user = u.user_id,
                    "racine utilisateur inutilisable : {e}"
                ),
            }
        }
    }
    // §6: ETag intent journals (locked: a single instance), replay of interrupted propagations.
    let jdir = cfg.state_dir.join("journal");
    std::fs::create_dir_all(&jdir)?;
    for t in registry.all() {
        let pending = t.journal().open(&jdir.join(format!("{}.log", t.name())))?;
        for (user, dir) in &pending {
            let r = SafePath::new(user)
                .map_err(|e| std::io::Error::other(e.to_string()))
                .and_then(|p| t.data_root().open_subdir(&p))
                .and_then(|root| root.renew_etags_lenient(dir.as_ref()));
            if let Err(e) = r {
                tracing::error!(tenant = t.name(), user, "ETag journal replay: {e}");
            }
        }
        if !pending.is_empty() {
            tracing::warn!(
                tenant = t.name(),
                n = pending.len(),
                "interrupted ETag propagations replayed"
            );
        }
        t.journal().replayed()?;
    }
    let settings = http::Settings {
        nc_version: cfg
            .nc_version()
            .ok_or_else(|| beastbox::Error::Config("nextcloud_version".into()))?,
        read_only: cfg.read_only,
        min_free_bytes: cfg.min_free_bytes,
        insecure_cookies: cfg.insecure_cookies,
        drop_max_file_bytes: cfg.drop_max_file_bytes,
        drop_max_total_bytes: cfg.drop_max_total_bytes,
        drop_max_files: cfg.drop_max_files,
        trash_days: cfg.trash_days,
        share_history_days: cfg.share_history_days,
        min_password: cfg.min_password,
        two_factor: cfg.tenants.iter().map(|t| (t.name.clone(), t.two_factor)).collect(),
    };
    if settings.insecure_cookies {
        tracing::warn!("insecure_cookies: cookies without Secure (HTTP test bench only, never in production)");
    }
    if settings.read_only {
        tracing::warn!("read-only mode (configuration)");
    }
    let mut app = http::App::new(registry, db, settings)?;
    // OIDC back channel (ADR-6): when a tenant has [tenant.oidc], open the Casper system.net channel now,
    // before cap_enter() — fail closed if the service or its limits cannot be had. Otherwise direct (unused).
    let tenants: Vec<&beastbox::tenant::TenantCtx> = app.registry.all().iter().collect();
    app.net = beastbox::auth::oidc_net::Net::for_tenants(&tenants)?;
    let app = Arc::new(app);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cfg.worker_threads)
        .max_blocking_threads(cfg.blocking_threads)
        .enable_io()
        .enable_time()
        .build()?;
    rt.block_on(async {
        let inner = tokio::net::TcpListener::bind(cfg.listen).await?;
        // Everything is open (roots, database, journals, socket, CA bundle, secret): from here on, no more
        // paths (Capsicum).
        fs::enter_capability_mode()?;
        tracing::info!(listen = %cfg.listen, tenants = app.registry.all().len(), "beastbox started");
        // Frees inactive search indexes (a simple in-memory sweep, no I/O).
        let idle = app.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                for t in idle.registry.all() {
                    t.index().sweep(beastbox::index::IDLE);
                }
            }
        });
        // Trash retention (§6): once an hour, only reads the users' `.trash/`.
        let purge = app.clone();
        tokio::spawn(async move {
            loop {
                let a = purge.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    expire_trash(&a);
                    expire_history(&a);
                })
                .await;
                tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
            }
        });
        http::serve(
            inner,
            cfg.trusted_proxies.clone(),
            cfg.max_connections,
            http::HEADER_TIMEOUT,
            http::router(app),
            shutdown(),
        )
        .await;
        Ok(())
    })
}

async fn shutdown() {
    use tokio::signal::unix::{SignalKind, signal};
    match (signal(SignalKind::terminate()), signal(SignalKind::interrupt())) {
        (Ok(mut term), Ok(mut int)) => {
            tokio::select! { _ = term.recv() => {}, _ = int.recv() => {} }
        }
        // Without signal handling, we only stop on SIGKILL: acceptable (atomic writes).
        _ => std::future::pending().await,
    }
}

/// Public link history: older than `share_history_days` or beyond the per-user cap, for each tenant.
fn expire_history(app: &http::App) {
    for t in app.registry.all() {
        match app.db.share_events_purge(t, app.settings.share_history_days) {
            Ok(0) => {}
            Ok(n) => tracing::info!(tenant = t.name(), events = n, "link history: events purged"),
            Err(e) => tracing::warn!(tenant = t.name(), "link history: purge failed: {e}"),
        }
    }
}

/// Permanently deletes trash items older than `trash_days`, for every user of every tenant.
fn expire_trash(app: &http::App) {
    let days = app.settings.trash_days;
    if days == 0 {
        return;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let before = i64::try_from(now.saturating_sub(u64::from(days) * 86_400)).unwrap_or(0);
    for t in app.registry.all() {
        let Ok(users) = t.data_root().read_dir(None) else {
            continue;
        };
        for (name, meta) in users.filter_map(Result::ok) {
            let Ok(p) = beastbox::fs::SafePath::new(&name) else {
                continue;
            };
            if !meta.is_dir {
                continue;
            }
            match t.data_root().open_subdir(&p).and_then(|r| r.trash_expire(before)) {
                Ok(0) => {}
                Ok(n) => {
                    tracing::info!(tenant = t.name(), user = %name, items = n, days, "trash: expired items deleted")
                }
                Err(e) => tracing::warn!(tenant = t.name(), user = %name, "trash: expiry failed: {e}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(a: &str) -> Result<Parsed, String> {
        parse(a.split_whitespace().map(String::from))
    }

    #[test]
    fn command_line() {
        let def = PathBuf::from(DEFAULT_CONFIG);
        assert_eq!(p("serve"), Ok(Parsed::Run(def.clone(), Cmd::Serve)));
        assert_eq!(
            p("manifest --tenant a --user alice"),
            Ok(Parsed::Run(
                def.clone(),
                Cmd::Manifest {
                    tenant: "a".into(),
                    user: Some("alice".into())
                }
            ))
        );
        assert!(
            p("manifest --tenant a --path x").is_err(),
            "--path makes no sense for manifest"
        );
        assert!(p("manifest --user alice").is_err(), "--tenant obligatoire");
        assert_eq!(
            p("restore --tenant a --user alice --from /snap --path Docs/a.pdf"),
            Ok(Parsed::Run(
                def.clone(),
                Cmd::Restore {
                    tenant: "a".into(),
                    user: "alice".into(),
                    from: "/snap".into(),
                    path: "Docs/a.pdf".into(),
                    to: None
                }
            ))
        );
        for (arg, n) in [("1", 1), ("8", 8), ("4", 4)] {
            assert!(
                matches!(p(&format!("rescan --tenant a --readers {arg}")), Ok(Parsed::Run(_, Cmd::Rescan { readers, .. })) if readers == n)
            );
        }
        for missing in [
            "restore --user alice --from /s --path p",
            "restore --tenant a --from /s --path p",
            "restore --tenant a --user alice --path p",
            "restore --tenant a --user alice --from /s",
            "restore --tenant a --user alice --from /s --path p --admin",
            "restore --tenant a --user alice --from /s --from /t --path p",
            "rescan --tenant a --from /s",
            "rescan --tenant a --to x",
            "rescan --tenant a --readers 0",
            "rescan --tenant a --readers 9",
            "rescan --tenant a --readers huit",
            "rescan --tenant a --readers 4 --readers 2",
            "manifest --tenant a --readers 4",
            "restore --tenant a --user alice --from /s --path p --to x --to y",
        ] {
            assert!(p(missing).is_err(), "{missing}");
        }
        assert!(matches!(
            p("restore --tenant a --user alice --from /s --path p --to Archives/x"),
            Ok(Parsed::Run(_, Cmd::Restore { to: Some(t), .. })) if t == "Archives/x"
        ));
        // The bound the message names is the one the code enforces.
        let bound = format!("1 to {}", beastbox::fs::RESCAN_READERS);
        assert!(p("rescan --tenant a --readers 9").unwrap_err().contains(&bound));
        assert!(p("rescan --tenant a --readers 0").unwrap_err().contains(&bound));
        assert!(p("rescan --tenant a --readers").is_err());
        assert_eq!(
            p("-c /x.toml check-config"),
            Ok(Parsed::Run("/x.toml".into(), Cmd::CheckConfig))
        );
        assert_eq!(
            p("check-config --config /y"),
            Ok(Parsed::Run("/y".into(), Cmd::CheckConfig))
        );
        assert_eq!(
            p("user add --tenant a alice --admin"),
            Ok(Parsed::Run(
                def.clone(),
                Cmd::User {
                    cmd: UserCmd::Add {
                        tenant: "a".into(),
                        name: "alice".into(),
                        admin: true,
                        oidc: false,
                    }
                }
            ))
        );
        // SSO: `--oidc` on `user add`, and the link command with its subject.
        assert_eq!(
            p("user add --tenant a alice --oidc"),
            Ok(Parsed::Run(
                def.clone(),
                Cmd::User {
                    cmd: UserCmd::Add {
                        tenant: "a".into(),
                        name: "alice".into(),
                        admin: false,
                        oidc: true,
                    }
                }
            ))
        );
        assert_eq!(
            p("user oidc-link --tenant a alice --subject 8f14e45f"),
            Ok(Parsed::Run(
                def.clone(),
                Cmd::User {
                    cmd: UserCmd::OidcLink {
                        tenant: "a".into(),
                        name: "alice".into(),
                        subject: "8f14e45f".into(),
                    }
                }
            ))
        );
        for bad in [
            "user oidc-link --tenant a alice", // no subject
            "user oidc-link --tenant a alice --subject s --oidc",
            "user oidc-link --tenant a alice --subject s --admin",
            "user add --tenant a alice --subject s", // subject only with oidc-link
            "user list --tenant a --oidc",
            "serve --oidc",
        ] {
            assert!(p(bad).is_err(), "{bad}");
        }
        assert_eq!(
            p("user passwd alice --tenant a"),
            Ok(Parsed::Run(
                def.clone(),
                Cmd::User {
                    cmd: UserCmd::Passwd {
                        tenant: "a".into(),
                        name: "alice".into()
                    }
                }
            ))
        );
        for (verb, active) in [("enable", true), ("disable", false)] {
            assert_eq!(
                p(&format!("user {verb} bob --tenant a")),
                Ok(Parsed::Run(
                    def.clone(),
                    Cmd::User {
                        cmd: UserCmd::SetActive {
                            tenant: "a".into(),
                            name: "bob".into(),
                            active
                        }
                    }
                ))
            );
            assert!(p(&format!("user {verb} bob")).is_err()); // tenant required
            assert!(p(&format!("user {verb} bob --tenant a --admin")).is_err());
        }
        assert_eq!(
            p("user 2fa-reset bob --tenant a"),
            Ok(Parsed::Run(
                def.clone(),
                Cmd::User {
                    cmd: UserCmd::TotpReset {
                        tenant: "a".into(),
                        name: "bob".into()
                    }
                }
            ))
        );
        assert!(p("user 2fa-reset bob").is_err());
        assert!(p("user 2fa-reset --tenant a").is_err());
        for cmd in ["enable", "disable", "2fa-reset"] {
            for extra in ["--user u", "--path p", "--admin"] {
                assert!(
                    p(&format!("user {cmd} bob --tenant a {extra}")).is_err(),
                    "{cmd} {extra}"
                );
            }
        }
        assert_eq!(
            p("rescan --tenant a --path Photos/2026"),
            Ok(Parsed::Run(
                def.clone(),
                Cmd::Rescan {
                    tenant: "a".into(),
                    user: None,
                    path: Some("Photos/2026".into()),
                    readers: beastbox::fs::RESCAN_READERS
                }
            ))
        );
        assert_eq!(p("--help"), Ok(Parsed::Help));
        assert_eq!(p("serve -V"), Ok(Parsed::Version));
        for bad in [
            "",
            "frobnicate",
            "user add alice",
            "user list --tenant",
            "verify --tenant a --tenant b",
            "serve --tenant a",
            "user list --tenant a --admin",
            "rescan --tenant a --bogus",
            "user add --tenant a",
        ] {
            assert!(p(bad).is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn restore_report_lines() {
        let to = SafePath::new("Docs/a (restored 2026-11-17).pdf").unwrap();
        let mut r = fs::CopyReport {
            files: 3,
            dirs: 1,
            skipped: 0,
        };
        assert_eq!(
            restore_report("alice", "Docs/a.pdf", &to, &r),
            "alice: Docs/a.pdf restored as Docs/a (restored 2026-11-17).pdf (3 files, 1 folders)"
        );
        r.skipped = 1;
        assert!(
            restore_report("alice", "Docs/a.pdf", &to, &r)
                .ends_with("folders)\n  1 items of the source passed over (link, special file, name not allowed)")
        );
    }
}
