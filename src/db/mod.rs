//! SQLite: application state only (§5), never the files. All SQL lives here, behind functions
//! that require a `TenantCtx`; every table carries `tenant_id` in its primary key and foreign keys
//! are composite (§4.1).
//!
//! Blocking calls: from async, always via `spawn_blocking` (§0.4).
//! shortcut: a single connection behind a Mutex (serializes queries); switch to a read pool + one
//! writer if contention is measured.

use crate::tenant::TenantCtx;
use crate::{Error, Result};
use rusqlite::{Connection, params};
use std::path::Path;

/// Numbered migrations: index + 1 is the value of `PRAGMA user_version` after applying.
const MIGRATIONS: &[&str] = &[
    r"
CREATE TABLE tenant (
    tenant_id   TEXT PRIMARY KEY,
    created_at  INTEGER NOT NULL
) STRICT;

CREATE TABLE user (
    tenant_id     TEXT NOT NULL REFERENCES tenant(tenant_id),
    user_id       TEXT NOT NULL,
    password_hash TEXT,                       -- argon2id, mot de passe humain (web, login flow)
    role          TEXT NOT NULL CHECK (role IN ('admin', 'user')),
    active        INTEGER NOT NULL DEFAULT 1,
    quota_bytes   INTEGER,
    created_at    INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
) STRICT;

CREATE TABLE app_token (                      -- mots de passe d'application (WebDAV, OCS)
    tenant_id    TEXT NOT NULL,
    token_id     TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    mac          BLOB NOT NULL,               -- HMAC-SHA-256(tenant key, token)
    label        TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    expires_at   INTEGER,
    PRIMARY KEY (tenant_id, token_id),
    UNIQUE (tenant_id, mac),
    FOREIGN KEY (tenant_id, user_id) REFERENCES user(tenant_id, user_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE session (
    tenant_id    TEXT NOT NULL,
    session_id   TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    mac          BLOB NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, session_id),
    UNIQUE (tenant_id, mac),
    FOREIGN KEY (tenant_id, user_id) REFERENCES user(tenant_id, user_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE share (
    tenant_id      TEXT NOT NULL,
    share_id       TEXT NOT NULL,
    user_id        TEXT NOT NULL,
    mac            BLOB NOT NULL,             -- digest of the public token
    fileid         BLOB NOT NULL,             -- persistent identity (§6)
    path_hint      TEXT NOT NULL,
    perms          TEXT NOT NULL CHECK (perms IN ('read', 'drop')),
    password_hash  TEXT,
    expires_at     INTEGER,
    max_downloads  INTEGER,
    download_count INTEGER NOT NULL DEFAULT 0,
    last_access_at INTEGER,
    revoked_at     INTEGER,
    created_at     INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, share_id),
    UNIQUE (tenant_id, mac),
    FOREIGN KEY (tenant_id, user_id) REFERENCES user(tenant_id, user_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE audit (
    tenant_id  TEXT NOT NULL REFERENCES tenant(tenant_id),
    audit_id   INTEGER NOT NULL,
    at         INTEGER NOT NULL,
    actor      TEXT,
    action     TEXT NOT NULL,
    result     TEXT NOT NULL,
    ip         TEXT,
    PRIMARY KEY (tenant_id, audit_id)
) STRICT;
",
    r"
-- J3: bytes received by a drop link (total limit per link, §8).
ALTER TABLE share ADD COLUMN drop_bytes INTEGER NOT NULL DEFAULT 0;
",
    r"
-- J4: public link history (downloads, archives, drops, refused passwords), no IP (§8).
-- Kept after the link is revoked (revoking does not delete the `share` row); bounded in time and number.
CREATE TABLE share_event (
    tenant_id  TEXT NOT NULL,
    event_id   INTEGER NOT NULL,              -- croissant par tenant
    share_id   TEXT NOT NULL,
    user_id    TEXT NOT NULL,                 -- link owner
    at         INTEGER NOT NULL,              -- last event of the group
    kind       TEXT NOT NULL CHECK (kind IN ('download', 'zip', 'drop', 'denied')),
    path       TEXT NOT NULL,                 -- relative to the link (first file of a group of drops)
    count      INTEGER NOT NULL DEFAULT 1,    -- grouped events
    bytes      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, event_id),
    FOREIGN KEY (tenant_id, share_id) REFERENCES share(tenant_id, share_id) ON DELETE CASCADE
) STRICT;
CREATE INDEX share_event_by_user ON share_event (tenant_id, user_id, at);
CREATE INDEX share_event_by_share ON share_event (tenant_id, share_id, event_id);
",
    r"
-- J4: state of a link whose target moved (noticed on use: the link does not follow its target).
-- 'trash' = target in the trash: link suspended, resumed if it is restored (revoked_at stays NULL);
-- 'gone' = target renamed, moved or permanently deleted: link ended (with revoked_at).
ALTER TABLE share ADD COLUMN end_reason TEXT CHECK (end_reason IN ('gone', 'trash'));
",
    r"
-- 0.9: files received by a drop link (count limit per link, so that empty files cannot flood the folder).
ALTER TABLE share ADD COLUMN drop_files INTEGER NOT NULL DEFAULT 0;
",
    r"
-- 0.11: link options set from the clients and the web page: read and upload (folders), label, note to the guest,
-- download hidden (view only).
ALTER TABLE share ADD COLUMN upload INTEGER NOT NULL DEFAULT 0;
ALTER TABLE share ADD COLUMN label TEXT NOT NULL DEFAULT '';
ALTER TABLE share ADD COLUMN note TEXT NOT NULL DEFAULT '';
ALTER TABLE share ADD COLUMN hide_download INTEGER NOT NULL DEFAULT 0;
",
    r"
-- 0.11: the owner's actions in the link history too (created, revoked, from the web page or a client). SQLite cannot
-- change a CHECK: the table is rebuilt, rows kept.
CREATE TABLE share_event_new (
    tenant_id  TEXT NOT NULL,
    event_id   INTEGER NOT NULL,
    share_id   TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    at         INTEGER NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('download', 'zip', 'drop', 'denied', 'created', 'revoked')),
    path       TEXT NOT NULL,
    count      INTEGER NOT NULL DEFAULT 1,
    bytes      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, event_id),
    FOREIGN KEY (tenant_id, share_id) REFERENCES share(tenant_id, share_id) ON DELETE CASCADE
) STRICT;
INSERT INTO share_event_new (tenant_id, event_id, share_id, user_id, at, kind, path, count, bytes)
    SELECT tenant_id, event_id, share_id, user_id, at, kind, path, count, bytes FROM share_event;
DROP TABLE share_event;
ALTER TABLE share_event_new RENAME TO share_event;
CREATE INDEX share_event_by_user ON share_event (tenant_id, user_id, at);
CREATE INDEX share_event_by_share ON share_event (tenant_id, share_id, event_id);
",
    // Password set by the administrator (account created, `user passwd`): the user chooses theirs at the next sign-in.
    "ALTER TABLE user ADD COLUMN must_change INTEGER NOT NULL DEFAULT 0;",
    // Two-step verification: sealed TOTP secret (NULL: off), last time step used (each code works once), recovery
    // codes (digests, single use), sessions waiting for the code (they open nothing else).
    "
ALTER TABLE user ADD COLUMN totp_secret BLOB;
ALTER TABLE user ADD COLUMN totp_last INTEGER NOT NULL DEFAULT 0;
ALTER TABLE session ADD COLUMN pending INTEGER NOT NULL DEFAULT 0;
CREATE TABLE recovery_code (
    tenant_id  TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    mac        BLOB NOT NULL,
    PRIMARY KEY (tenant_id, user_id, mac),
    FOREIGN KEY (tenant_id, user_id) REFERENCES user(tenant_id, user_id) ON DELETE CASCADE
) STRICT;
",
    // Single sign-on (OIDC): a provider identity is bound to an account by `user oidc-link` only. Never by name or
    // e-mail. `password_hash` stays NULL for a linked account (no password login; `user passwd` unlinks it).
    "
ALTER TABLE user ADD COLUMN oidc_issuer  TEXT;
ALTER TABLE user ADD COLUMN oidc_subject TEXT;
CREATE UNIQUE INDEX user_oidc ON user(tenant_id, oidc_issuer, oidc_subject) WHERE oidc_subject IS NOT NULL;
",
];

/// Precision of an app password's last use (seconds).
const TOKEN_SEEN_EVERY: i64 = 3600;

/// Every application query. The audit (test below) requires `tenant_id` in each one.
const Q_TENANT_SYNC: &str = "INSERT OR IGNORE INTO tenant (tenant_id, created_at) VALUES (?1, ?2)";
const Q_USER_ADD: &str = "INSERT INTO user (tenant_id, user_id, password_hash, role, created_at, must_change) VALUES (?1, ?2, ?3, ?4, ?5, 1)";
// OIDC account: no password, nothing to change. It signs in only once an identity is linked.
const Q_USER_ADD_OIDC: &str = "INSERT INTO user (tenant_id, user_id, password_hash, role, created_at, must_change) VALUES (?1, ?2, NULL, ?3, ?4, 0)";
const Q_USER_OIDC_LINK: &str = "UPDATE user SET oidc_issuer = ?3, oidc_subject = ?4, password_hash = NULL, must_change = 0 \
     WHERE tenant_id = ?1 AND user_id = ?2 AND active = 1 AND oidc_subject IS NULL";
const Q_USER_OIDC_UNLINK: &str = "UPDATE user SET oidc_issuer = NULL, oidc_subject = NULL, password_hash = ?3, must_change = 1 \
     WHERE tenant_id = ?1 AND user_id = ?2 AND oidc_subject IS NOT NULL";
const Q_USER_BY_OIDC: &str =
    "SELECT user_id FROM user WHERE tenant_id = ?1 AND oidc_issuer = ?2 AND oidc_subject = ?3 AND active = 1";
const Q_AUDIT_ADD: &str = "INSERT INTO audit (tenant_id, audit_id, at, actor, action, result, ip) VALUES (?1, \
     (SELECT coalesce(max(audit_id), 0) + 1 FROM audit WHERE tenant_id = ?1), ?2, ?3, ?4, ?5, ?6)";
const Q_AUDIT_LIST: &str = "SELECT at, actor, action, result FROM audit WHERE tenant_id = ?1 ORDER BY audit_id";
const Q_USER_ROLE: &str = "SELECT role FROM user WHERE tenant_id = ?1 AND user_id = ?2";
const Q_USER_LIST: &str =
    "SELECT user_id, role, active, totp_secret IS NOT NULL FROM user WHERE tenant_id = ?1 ORDER BY user_id LIMIT ?2";
const Q_USER_HASH: &str = "SELECT password_hash FROM user WHERE tenant_id = ?1 AND user_id = ?2 AND active = 1";
const Q_TOKEN_ADD: &str =
    "INSERT INTO app_token (tenant_id, token_id, user_id, mac, label, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)";
const Q_TOKEN_ADD_PENDING: &str = "INSERT INTO app_token (tenant_id, token_id, user_id, mac, label, created_at, expires_at) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
// `expires_at` is only set on a password waiting for its first use (QR code): used once, it no longer expires.
const Q_TOKEN_PENDING_DEL: &str =
    "DELETE FROM app_token WHERE tenant_id = ?1 AND user_id = ?2 AND expires_at IS NOT NULL AND last_used_at IS NULL";
const Q_TOKEN_EXPIRED_DEL: &str =
    "DELETE FROM app_token WHERE tenant_id = ?1 AND expires_at IS NOT NULL AND expires_at <= ?2";
const Q_TOKEN_KEEP: &str =
    "UPDATE app_token SET expires_at = NULL, last_used_at = ?3 WHERE tenant_id = ?1 AND mac = ?2";
const Q_TOKEN_USER: &str = "SELECT t.user_id, t.last_used_at, t.expires_at FROM app_token t JOIN user u ON u.tenant_id = t.tenant_id AND u.user_id = t.user_id \
     WHERE t.tenant_id = ?1 AND t.mac = ?2 AND u.active = 1 AND (t.expires_at IS NULL OR t.expires_at > ?3)";
const Q_USER_SET_HASH: &str =
    "UPDATE user SET password_hash = ?3, must_change = ?4 WHERE tenant_id = ?1 AND user_id = ?2";
const Q_USER_MUST_CHANGE: &str = "SELECT must_change FROM user WHERE tenant_id = ?1 AND user_id = ?2 AND active = 1";
const Q_USER_SET_ACTIVE: &str = "UPDATE user SET active = ?3 WHERE tenant_id = ?1 AND user_id = ?2";
const Q_TOKEN_LIST: &str = "SELECT token_id, label, created_at, last_used_at, expires_at FROM app_token \
     WHERE tenant_id = ?1 AND user_id = ?2 ORDER BY created_at DESC LIMIT 200";
const Q_TOKEN_SEEN: &str = "UPDATE app_token SET last_used_at = ?3 WHERE tenant_id = ?1 AND mac = ?2";
const Q_TOKEN_DEL: &str = "DELETE FROM app_token WHERE tenant_id = ?1 AND user_id = ?2 AND token_id = ?3";
const Q_SESSION_ADD: &str = "INSERT INTO session (tenant_id, session_id, user_id, mac, created_at, expires_at, pending) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
const Q_SESSION_USER: &str = "SELECT s.user_id, u.must_change, s.pending, u.totp_secret IS NOT NULL, \
     u.password_hash IS NOT NULL, s.created_at FROM session s JOIN user u ON u.tenant_id = s.tenant_id AND u.user_id = s.user_id \
     WHERE s.tenant_id = ?1 AND s.mac = ?2 AND u.active = 1 AND s.expires_at > ?3";
const Q_SESSION_DEL: &str = "DELETE FROM session WHERE tenant_id = ?1 AND mac = ?2";
const Q_TOTP_GET: &str = "SELECT totp_secret, totp_last FROM user WHERE tenant_id = ?1 AND user_id = ?2 AND active = 1";
const Q_TOTP_SET: &str = "UPDATE user SET totp_secret = ?3, totp_last = ?4 WHERE tenant_id = ?1 AND user_id = ?2";
// Atomic anti-replay: two requests with the same code cannot both move the last step forward.
const Q_TOTP_USE: &str = "UPDATE user SET totp_last = ?3 \
     WHERE tenant_id = ?1 AND user_id = ?2 AND totp_secret IS NOT NULL AND totp_last < ?3";
const Q_RECOVERY_DEL_ALL: &str = "DELETE FROM recovery_code WHERE tenant_id = ?1 AND user_id = ?2";
const Q_RECOVERY_ADD: &str = "INSERT OR IGNORE INTO recovery_code (tenant_id, user_id, mac) VALUES (?1, ?2, ?3)";
const Q_RECOVERY_USE: &str = "DELETE FROM recovery_code WHERE tenant_id = ?1 AND user_id = ?2 AND mac = ?3 \
     AND EXISTS (SELECT 1 FROM user u WHERE u.tenant_id = ?1 AND u.user_id = ?2 AND u.totp_secret IS NOT NULL)";
const Q_RECOVERY_COUNT: &str = "SELECT count(*) FROM recovery_code WHERE tenant_id = ?1 AND user_id = ?2";
const Q_SESSION_DEL_OTHERS: &str = "DELETE FROM session WHERE tenant_id = ?1 AND user_id = ?2 AND mac != ?3";
const Q_SESSION_DEL_USER: &str = "DELETE FROM session WHERE tenant_id = ?1 AND user_id = ?2";
const Q_SESSION_PURGE: &str = "DELETE FROM session WHERE tenant_id = ?1 AND expires_at <= ?2";
const Q_SHARE_ADD: &str = "INSERT INTO share (tenant_id, share_id, user_id, mac, fileid, path_hint, perms, password_hash, \
     expires_at, max_downloads, created_at, upload, label, note, hide_download) \
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)";
// The owner's account must be active: a disabled account's links answer like unknown ones until it is enabled again.
const Q_SHARE_BY_MAC: &str = "SELECT s.share_id, s.user_id, s.fileid, s.path_hint, s.perms, s.password_hash, s.expires_at, \
     s.max_downloads, s.download_count, s.last_access_at, s.revoked_at, s.created_at, s.drop_bytes, s.end_reason, s.upload, \
     s.label, s.note, s.hide_download FROM share s JOIN user u ON u.tenant_id = s.tenant_id AND u.user_id = s.user_id \
     WHERE s.tenant_id = ?1 AND s.mac = ?2 AND u.active = 1";
const Q_SHARE_LIST: &str = "SELECT share_id, user_id, fileid, path_hint, perms, password_hash, expires_at, max_downloads, \
     download_count, last_access_at, revoked_at, created_at, drop_bytes, end_reason, upload, label, note, hide_download FROM share \
     WHERE tenant_id = ?1 AND user_id = ?2 AND revoked_at IS NULL AND end_reason IS NULL \
     AND (expires_at IS NULL OR expires_at > ?3) \
     AND (max_downloads IS NULL OR download_count < max_downloads) ORDER BY created_at DESC LIMIT 500";
const Q_SHARE_DROP_RELEASE: &str = "UPDATE share SET drop_bytes = max(drop_bytes - ?3, 0), drop_files = max(drop_files - 1, 0) \
     WHERE tenant_id = ?1 AND share_id = ?2";
const Q_SHARE_GONE: &str = "UPDATE share SET revoked_at = ?3, end_reason = 'gone' \
     WHERE tenant_id = ?1 AND share_id = ?2 AND revoked_at IS NULL";
const Q_SHARE_SUSPEND: &str = "UPDATE share SET end_reason = 'trash' \
     WHERE tenant_id = ?1 AND share_id = ?2 AND revoked_at IS NULL AND end_reason IS NULL";
const Q_SHARE_RESUME: &str = "UPDATE share SET end_reason = NULL \
     WHERE tenant_id = ?1 AND share_id = ?2 AND revoked_at IS NULL AND end_reason = 'trash'";
const Q_SHARE_SUSPENDED: &str = "SELECT share_id, user_id, fileid, path_hint, perms, password_hash, expires_at, \
     max_downloads, download_count, last_access_at, revoked_at, created_at, drop_bytes, end_reason, upload, label, note, hide_download FROM share \
     WHERE tenant_id = ?1 AND user_id = ?2 AND revoked_at IS NULL AND end_reason = 'trash' LIMIT 500";
const Q_SHARE_REVOKE: &str =
    "UPDATE share SET revoked_at = ?4 WHERE tenant_id = ?1 AND user_id = ?2 AND share_id = ?3 AND revoked_at IS NULL";
const Q_SHARE_UPDATE: &str = "UPDATE share SET perms = ?4, password_hash = ?5, expires_at = ?6, upload = ?7, \
     label = ?8, note = ?9, hide_download = ?10 \
     WHERE tenant_id = ?1 AND user_id = ?2 AND share_id = ?3 AND revoked_at IS NULL";
// Counter incremented only if the limit is not reached: no overrun through concurrent requests.
const Q_SHARE_HIT: &str = "UPDATE share SET download_count = download_count + 1, last_access_at = ?3 \
     WHERE tenant_id = ?1 AND share_id = ?2 AND (max_downloads IS NULL OR download_count < max_downloads)";
const Q_SHARE_SEEN: &str = "UPDATE share SET last_access_at = ?3 WHERE tenant_id = ?1 AND share_id = ?2";
const Q_SHARE_DROP: &str = "UPDATE share SET drop_bytes = drop_bytes + ?3, drop_files = drop_files + 1 \
     WHERE tenant_id = ?1 AND share_id = ?2 AND drop_bytes + ?3 <= ?4 AND drop_files < ?5";
const Q_EVENT_LAST: &str = "SELECT event_id, kind, path, at FROM share_event WHERE tenant_id = ?1 AND share_id = ?2 \
     ORDER BY event_id DESC LIMIT 1";
const Q_EVENT_BUMP: &str =
    "UPDATE share_event SET count = count + 1, bytes = bytes + ?3, at = ?4 WHERE tenant_id = ?1 AND event_id = ?2";
const Q_EVENT_ADD: &str = "INSERT INTO share_event (tenant_id, event_id, share_id, user_id, at, kind, path, bytes) \
     VALUES (?1, (SELECT coalesce(max(event_id), 0) + 1 FROM share_event WHERE tenant_id = ?1), ?2, ?3, ?4, ?5, ?6, ?7)";
// The whole tenant: older than the retention, or beyond the `?3` newest of each user.
const Q_EVENT_PURGE: &str = "DELETE FROM share_event WHERE tenant_id = ?1 AND (at < ?2 OR event_id IN \
     (SELECT event_id FROM (SELECT event_id, row_number() OVER (PARTITION BY user_id ORDER BY event_id DESC) AS n \
     FROM share_event WHERE tenant_id = ?1) WHERE n > ?3))";
const Q_EVENT_LIST: &str = "SELECT e.share_id, e.at, e.kind, e.path, e.count, e.bytes, s.path_hint, s.revoked_at, \
     s.end_reason, s.expires_at, s.max_downloads, s.download_count \
     FROM share_event e JOIN share s ON s.tenant_id = e.tenant_id AND s.share_id = e.share_id \
     WHERE e.tenant_id = ?1 AND e.user_id = ?2 AND (?3 = '' OR e.share_id = ?3) AND e.at >= ?4 \
     AND (?7 = 0 OR e.kind NOT IN ('created', 'revoked')) \
     ORDER BY e.at DESC, e.event_id DESC LIMIT ?5 OFFSET ?6";
const Q_EVENT_COUNT: &str = "SELECT count(*) FROM share_event WHERE tenant_id = ?1 AND user_id = ?2 \
     AND (?3 = '' OR share_id = ?3) AND at >= ?4 AND (?5 = 0 OR kind NOT IN ('created', 'revoked'))";
const Q_EVENT_SHARES: &str = "SELECT s.share_id, s.path_hint, s.revoked_at, s.end_reason, s.expires_at, s.max_downloads, \
     s.download_count FROM share s WHERE s.tenant_id = ?1 \
     AND s.user_id = ?2 AND EXISTS (SELECT 1 FROM share_event e WHERE e.tenant_id = s.tenant_id AND e.share_id = s.share_id \
     AND e.at >= ?3) ORDER BY s.path_hint, s.created_at LIMIT 500";

#[cfg(test)]
const QUERIES: &[&str] = &[
    Q_EVENT_LAST,
    Q_EVENT_BUMP,
    Q_EVENT_ADD,
    Q_EVENT_PURGE,
    Q_EVENT_LIST,
    Q_EVENT_COUNT,
    Q_EVENT_SHARES,
    Q_TOKEN_LIST,
    Q_TOKEN_DEL,
    Q_SESSION_ADD,
    Q_SESSION_USER,
    Q_SESSION_DEL,
    Q_SESSION_DEL_USER,
    Q_SESSION_DEL_OTHERS,
    Q_SESSION_PURGE,
    Q_SHARE_ADD,
    Q_SHARE_BY_MAC,
    Q_SHARE_LIST,
    Q_SHARE_REVOKE,
    Q_SHARE_GONE,
    Q_SHARE_DROP_RELEASE,
    Q_SHARE_SUSPEND,
    Q_SHARE_RESUME,
    Q_SHARE_SUSPENDED,
    Q_SHARE_HIT,
    Q_SHARE_SEEN,
    Q_SHARE_DROP,
    Q_TENANT_SYNC,
    Q_USER_SET_HASH,
    Q_USER_SET_ACTIVE,
    Q_USER_ADD,
    Q_USER_LIST,
    Q_USER_ROLE,
    Q_USER_HASH,
    Q_USER_MUST_CHANGE,
    Q_TOTP_GET,
    Q_TOTP_SET,
    Q_TOTP_USE,
    Q_RECOVERY_DEL_ALL,
    Q_RECOVERY_ADD,
    Q_RECOVERY_USE,
    Q_RECOVERY_COUNT,
    Q_TOKEN_ADD,
    Q_TOKEN_USER,
    Q_TOKEN_ADD_PENDING,
    Q_TOKEN_PENDING_DEL,
    Q_TOKEN_EXPIRED_DEL,
    Q_TOKEN_KEEP,
    Q_TOKEN_SEEN,
    Q_USER_ADD_OIDC,
    Q_USER_OIDC_LINK,
    Q_USER_OIDC_UNLINK,
    Q_USER_BY_OIDC,
    Q_AUDIT_ADD,
    Q_AUDIT_LIST,
];

pub struct Db {
    conn: std::sync::Mutex<Connection>,
}

/// App password (without the secret, never kept).
pub struct TokenRow {
    pub token_id: String,
    pub label: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    /// Waiting for its first use (QR code): gone at this time if unused.
    pub expires_at: Option<i64>,
}

/// Share link (§8). The public token is not stored: it is derived from `share_id` and the tenant key.
#[derive(Clone, Debug)]
pub struct ShareRow {
    pub share_id: String,
    pub user_id: String,
    pub fileid: Vec<u8>,
    pub path_hint: String,
    /// `read` (read-only) or `drop` (drop only).
    pub perms: String,
    pub password_hash: Option<String>,
    pub expires_at: Option<i64>,
    pub max_downloads: Option<i64>,
    pub download_count: i64,
    pub last_access_at: Option<i64>,
    pub revoked_at: Option<i64>,
    pub created_at: i64,
    pub drop_bytes: i64,
    /// Suspended because its target is in the trash.
    pub suspended: bool,
    pub opts: LinkOptions,
}

/// What a guest did with a link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareEventKind {
    /// A file downloaded.
    Download,
    /// A folder downloaded as an archive.
    Zip,
    /// A file dropped.
    Drop,
    /// Password refused.
    Denied,
    /// The owner created the link (web page or client).
    Created,
    /// The owner revoked the link (web page or client).
    Revoked,
}

impl ShareEventKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Download => "download",
            Self::Zip => "zip",
            Self::Drop => "drop",
            Self::Denied => "denied",
            Self::Created => "created",
            Self::Revoked => "revoked",
        }
    }
    fn parse(s: &str) -> Self {
        match s {
            "zip" => Self::Zip,
            "drop" => Self::Drop,
            "denied" => Self::Denied,
            "created" => Self::Created,
            "revoked" => Self::Revoked,
            _ => Self::Download,
        }
    }
}

/// An event of the link history (possibly a group: drops of the same upload, repeated attempts).
#[derive(Clone, Debug)]
pub struct ShareEvent {
    pub share_id: String,
    pub at: i64,
    pub kind: ShareEventKind,
    pub path: String,
    pub count: i64,
    pub bytes: i64,
    /// The link's target (path in the owner's space, empty = the whole space).
    pub share_path: String,
    /// The link no longer serves, and why.
    pub share_end: Option<ShareEnd>,
}

/// Why a link no longer serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShareEnd {
    /// Target in the trash: suspended, resumed if it is restored.
    Suspended,
    Revoked,
    Expired,
    /// Download limit reached.
    Exhausted,
    /// Target deleted, moved or renamed.
    Gone,
}

impl ShareEnd {
    /// Short English word, translated by the caller: "revoked", "expired"…
    pub fn label(self) -> &'static str {
        match self {
            Self::Suspended => "suspended: in the trash",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Exhausted => "exhausted",
            Self::Gone => "deleted or moved target",
        }
    }
}

/// End state of a link from its columns `revoked_at, end_reason, expires_at, max_downloads, download_count`, read
/// starting at column `i`.
fn share_end(r: &rusqlite::Row<'_>, i: usize, now: i64) -> rusqlite::Result<Option<ShareEnd>> {
    let revoked: Option<i64> = r.get(i)?;
    let reason: Option<String> = r.get(i + 1)?;
    let expires: Option<i64> = r.get(i + 2)?;
    let (max, count): (Option<i64>, i64) = (r.get(i + 3)?, r.get(i + 4)?);
    Ok(match () {
        _ if reason.as_deref() == Some("gone") => Some(ShareEnd::Gone),
        _ if revoked.is_some() => Some(ShareEnd::Revoked),
        _ if reason.as_deref() == Some("trash") => Some(ShareEnd::Suspended),
        _ if expires.is_some_and(|e| e <= now) => Some(ShareEnd::Expired),
        _ if max.is_some_and(|m| count >= m) => Some(ShareEnd::Exhausted),
        _ => None,
    })
}

/// A link that has history (filter of the Shared links page).
#[derive(Clone, Debug)]
pub struct EventShare {
    pub share_id: String,
    pub path_hint: String,
    pub end: Option<ShareEnd>,
}

/// Grouping window: a new event of the same link, of the same kind (and, for a download, of the same
/// file) within this interval extends the previous one instead of creating one (video played by ranges, repeated
/// password attempts, several files of the same drop).
pub const EVENT_GROUP_SECS: i64 = 10 * 60;
/// Events kept at most per user, at the hourly purge (200 in tests: same logic, without 20,000 writes).
pub const EVENTS_MAX: i64 = if cfg!(test) { 200 } else { 20_000 };

/// Parameters for creating a link.
pub struct NewShare<'a> {
    pub share_id: &'a str,
    pub user: &'a str,
    pub mac: &'a [u8; 32],
    pub fileid: &'a [u8],
    pub path_hint: &'a str,
    pub perms: &'a str,
    pub password_hash: Option<&'a str>,
    pub expires_at: Option<i64>,
    pub max_downloads: Option<i64>,
    pub opts: &'a LinkOptions,
}

/// Options of a link, beyond its access: upload into a read-only folder, label (for the owner), note (for the guest),
/// download hidden (view only).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LinkOptions {
    pub upload: bool,
    pub label: String,
    pub note: String,
    pub hide_download: bool,
}

fn share_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ShareRow> {
    Ok(ShareRow {
        share_id: r.get(0)?,
        user_id: r.get(1)?,
        fileid: r.get(2)?,
        path_hint: r.get(3)?,
        perms: r.get(4)?,
        password_hash: r.get(5)?,
        expires_at: r.get(6)?,
        max_downloads: r.get(7)?,
        download_count: r.get(8)?,
        last_access_at: r.get(9)?,
        revoked_at: r.get(10)?,
        created_at: r.get(11)?,
        drop_bytes: r.get(12)?,
        suspended: r.get::<_, Option<String>>(13)?.as_deref() == Some("trash"),
        opts: LinkOptions {
            upload: r.get(14)?,
            label: r.get(15)?,
            note: r.get(16)?,
            hide_download: r.get(17)?,
        },
    })
}

pub fn now_secs() -> i64 {
    now()
}

/// A web session as stored, with its account's state.
#[derive(Debug, PartialEq, Eq)]
pub struct SessionRow {
    pub user: String,
    /// Password set by the administrator, to be replaced.
    pub must_change: bool,
    /// Password checked, second step still to come.
    pub pending: bool,
    /// Two-step verification on for the account.
    pub totp: bool,
    /// The account has a human password (an account bound to single sign-on has none).
    pub has_password: bool,
    /// When this session was opened (Unix time): a recent sign-in, for what asks one.
    pub created: i64,
}

/// An `audit` row: when, who (`audit_in` explains `actor`), which action, its result.
#[derive(Debug, PartialEq, Eq)]
pub struct AuditRow {
    pub at: i64,
    pub actor: Option<String>,
    pub action: String,
    pub result: String,
}

pub struct UserRow {
    pub user_id: String,
    pub role: String,
    pub active: bool,
    /// Two-step verification on.
    pub totp: bool,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// One `audit` row, in or out of a transaction: the `audit_id` goes on from the tenant's last one.
fn audit_in(
    c: &Connection,
    t: &TenantCtx,
    actor: Option<&str>,
    action: &str,
    result: &str,
    ip: Option<&str>,
) -> rusqlite::Result<()> {
    c.execute(Q_AUDIT_ADD, params![t.name(), now(), actor, action, result, ip])?;
    Ok(())
}

impl Db {
    /// Opens (or creates as 0600 via the process umask) the database, applies the migrations.
    /// Before any migration of an existing database, a backup copy with `VACUUM INTO` (§0.2).
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;")?;
        let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        let version = usize::try_from(version).map_err(|_| Error::Config("negative user_version".into()))?;
        if version > MIGRATIONS.len() {
            return Err(Error::Config(format!(
                "database at version {version}, newer than this binary"
            )));
        }
        if version > 0 && version < MIGRATIONS.len() {
            let backup = path.with_extension(format!("v{version}-{}.bak", now()));
            conn.execute("VACUUM INTO ?1", params![backup.to_string_lossy()])?;
        }
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(version) {
            let tx = conn.unchecked_transaction()?;
            tx.execute_batch(sql)?;
            tx.pragma_update(None, "user_version", i64::try_from(i + 1).unwrap_or(i64::MAX))?;
            tx.commit()?;
        }
        Ok(Self {
            conn: std::sync::Mutex::new(conn),
        })
    }

    /// Tests elsewhere in the crate: every row of every table that belongs to `tenant`, as text, sorted (a fingerprint
    /// of the tenant's database state).
    #[cfg(test)]
    pub(crate) fn tenant_rows(&self, tenant: &str) -> Vec<String> {
        let Ok(c) = self.conn() else { return Vec::new() };
        let tables: Vec<String> = c
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND sql LIKE '%tenant_id%'")
            .and_then(|mut st| st.query_map([], |r| r.get(0))?.collect())
            .unwrap_or_default();
        let mut out = Vec::new();
        for t in tables {
            let Ok(mut st) = c.prepare(&format!("SELECT * FROM \"{t}\" WHERE tenant_id = ?1")) else {
                continue;
            };
            let n = st.column_count();
            let rows = st.query_map([tenant], |r| {
                Ok((0..n)
                    .map(|i| format!("{:?}", r.get::<_, rusqlite::types::Value>(i).ok()))
                    .collect::<Vec<_>>()
                    .join("|"))
            });
            if let Ok(rows) = rows {
                out.extend(rows.filter_map(|r| r.ok()).map(|r| format!("{t}: {r}")));
            }
        }
        out.sort();
        out
    }

    /// Tests elsewhere in the crate: every row of every table that belongs to `user` of `tenant` (the tables with a
    /// `user_id` column), as text, sorted.
    #[cfg(test)]
    pub(crate) fn user_rows(&self, tenant: &str, user: &str) -> Vec<String> {
        let c = self.conn().unwrap();
        let tables: Vec<String> = c
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND sql LIKE '%user_id%'")
            .and_then(|mut st| st.query_map([], |r| r.get(0))?.collect())
            .unwrap();
        let mut out = Vec::new();
        for t in tables {
            let mut st = c
                .prepare(&format!("SELECT * FROM \"{t}\" WHERE tenant_id = ?1 AND user_id = ?2"))
                .unwrap();
            let n = st.column_count();
            let rows = st
                .query_map([tenant, user], |r| {
                    Ok((0..n)
                        .map(|i| format!("{:?}", r.get::<_, rusqlite::types::Value>(i).ok()))
                        .collect::<Vec<_>>()
                        .join("|"))
                })
                .unwrap();
            out.extend(rows.map(|r| format!("{t}: {}", r.unwrap())));
        }
        out.sort();
        out
    }

    /// Tests elsewhere in the crate: a raw statement (moving time, forcing a state).
    #[cfg(test)]
    pub(crate) fn raw(&self, sql: &str) -> usize {
        self.conn().and_then(|c| Ok(c.execute(sql, [])?)).unwrap_or(0)
    }

    fn conn(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| Error::Invalid("database lock poisoned".into()))
    }

    /// Tenants come from the configuration; the database keeps their row for the foreign keys.
    pub fn sync_tenants(&self, tenants: &[TenantCtx]) -> Result<()> {
        for t in tenants {
            self.conn()?.execute(Q_TENANT_SYNC, params![t.name(), now()])?;
        }
        Ok(())
    }

    /// Adds an account whose password was set by the administrator: it must choose its own at the next sign-in.
    pub fn user_add(&self, t: &TenantCtx, user: &str, password_hash: &str, admin: bool) -> Result<()> {
        let role = if admin { "admin" } else { "user" };
        self.conn()?
            .execute(Q_USER_ADD, params![t.name(), user, password_hash, role, now()])
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
                    Error::Invalid(format!("user {user} already exists in {}", t.name()))
                }
                e => e.into(),
            })?;
        Ok(())
    }

    /// Adds an account without a password: it can only sign in through an identity linked to it (`user oidc-link`).
    pub fn user_add_oidc(&self, t: &TenantCtx, user: &str, admin: bool) -> Result<()> {
        let role = if admin { "admin" } else { "user" };
        self.conn()?
            .execute(Q_USER_ADD_OIDC, params![t.name(), user, role, now()])
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
                    Error::Invalid(format!("user {user} already exists in {}", t.name()))
                }
                e => e.into(),
            })?;
        Ok(())
    }

    /// Binds a provider identity (`issuer`, `subject`) to an active account that has none yet: one transaction, an
    /// `audit` row, the account keeps its TOTP secret and recovery codes, and its web sessions end. The password is
    /// cleared (a linked account has none). Refused if the account is unknown, disabled or already linked, or if the
    /// identity is already bound in this tenant.
    pub fn user_oidc_link(&self, t: &TenantCtx, user: &str, issuer: &str, subject: &str) -> Result<()> {
        let c = self.conn()?;
        let tx = c.unchecked_transaction()?;
        let n = tx
            .execute(Q_USER_OIDC_LINK, params![t.name(), user, issuer, subject])
            .map_err(|e| match e {
                rusqlite::Error::SqliteFailure(f, _) if f.code == rusqlite::ErrorCode::ConstraintViolation => {
                    Error::Invalid(format!("this identity is already linked to an account in {}", t.name()))
                }
                e => e.into(),
            })?;
        if n != 1 {
            return Err(Error::Invalid(format!(
                "unknown, disabled or already linked account in {}: {user}",
                t.name()
            )));
        }
        tx.execute(Q_SESSION_DEL_USER, params![t.name(), user])?;
        audit_in(&tx, t, Some(user), "oidc-link", "ok", None)?;
        tx.commit()?;
        Ok(())
    }

    /// The active account an identity is linked to, if any. The tenant comes from `TenantCtx`, never from a token.
    pub fn user_by_oidc(&self, t: &TenantCtx, issuer: &str, subject: &str) -> Result<Option<String>> {
        use rusqlite::OptionalExtension;
        Ok(self
            .conn()?
            .query_row(Q_USER_BY_OIDC, params![t.name(), issuer, subject], |r| r.get(0))
            .optional()?)
    }

    /// The recovery path for a linked account (`user passwd`): the identity is removed, a human password set, the user
    /// chooses their own at the next sign-in, the web sessions end, and the `audit` table records it. `false`: the
    /// account is unknown or not linked.
    pub fn user_oidc_unlink_with_password(&self, t: &TenantCtx, user: &str, password_hash: &str) -> Result<bool> {
        let c = self.conn()?;
        let tx = c.unchecked_transaction()?;
        let done = tx.execute(Q_USER_OIDC_UNLINK, params![t.name(), user, password_hash])? == 1;
        if done {
            tx.execute(Q_SESSION_DEL_USER, params![t.name(), user])?;
            audit_in(&tx, t, Some(user), "oidc-unlink", "ok", None)?;
        }
        tx.commit()?;
        Ok(done)
    }

    /// The `audit` rows of a tenant, oldest first (tests and diagnostics).
    pub fn audit_list(&self, t: &TenantCtx) -> Result<Vec<AuditRow>> {
        let c = self.conn()?;
        let mut st = c.prepare(Q_AUDIT_LIST)?;
        let rows = st.query_map(params![t.name()], |r| {
            Ok(AuditRow {
                at: r.get(0)?,
                actor: r.get(1)?,
                action: r.get(2)?,
                result: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Bounded list (§0.4): at most `limit` rows.
    /// An account's role (`admin` or `user`), if it exists.
    pub fn user_role(&self, t: &TenantCtx, user: &str) -> Result<Option<String>> {
        use rusqlite::OptionalExtension;
        Ok(self
            .conn()?
            .query_row(Q_USER_ROLE, params![t.name(), user], |r| r.get(0))
            .optional()?)
    }

    pub fn user_list(&self, t: &TenantCtx, limit: u32) -> Result<Vec<UserRow>> {
        let conn = self.conn()?;
        let mut st = conn.prepare(Q_USER_LIST)?;
        let rows = st.query_map(params![t.name(), limit], |r| {
            Ok(UserRow {
                user_id: r.get(0)?,
                role: r.get(1)?,
                active: r.get::<_, i64>(2)? != 0,
                totp: r.get::<_, i64>(3)? != 0,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Replaces the human password digest and ends the account's web sessions (a stolen session does not survive
    /// the change; app passwords stay). `must_change`: set by the administrator, to be replaced at the next sign-in.
    /// False if the account does not exist in this tenant.
    pub fn user_set_password_hash(&self, t: &TenantCtx, user: &str, hash: &str, must_change: bool) -> Result<bool> {
        let c = self.conn()?;
        let tx = c.unchecked_transaction()?;
        let found = tx.execute(Q_USER_SET_HASH, params![t.name(), user, hash, i64::from(must_change)])? == 1;
        tx.execute(Q_SESSION_DEL_USER, params![t.name(), user])?;
        tx.commit()?;
        Ok(found)
    }

    /// Enables or disables an account; disabling also ends its web sessions (enabling must not revive them). Its
    /// app passwords and links are only blocked while it is disabled (queries require `active = 1`). `false`: unknown.
    pub fn user_set_active(&self, t: &TenantCtx, user: &str, active: bool) -> Result<bool> {
        let c = self.conn()?;
        let tx = c.unchecked_transaction()?;
        let found = tx.execute(Q_USER_SET_ACTIVE, params![t.name(), user, i64::from(active)])? == 1;
        if !active {
            tx.execute(Q_SESSION_DEL_USER, params![t.name(), user])?;
        }
        tx.commit()?;
        Ok(found)
    }

    /// Whether an active account must still replace a password set by the administrator (`None`: unknown or disabled).
    pub fn user_must_change(&self, t: &TenantCtx, user: &str) -> Result<Option<bool>> {
        use rusqlite::OptionalExtension;
        Ok(self
            .conn()?
            .query_row(Q_USER_MUST_CHANGE, params![t.name(), user], |r| r.get::<_, i64>(0))
            .optional()?
            .map(|v| v != 0))
    }

    /// argon2id digest of an active account's human password.
    pub fn user_password_hash(&self, t: &TenantCtx, user: &str) -> Result<Option<String>> {
        use rusqlite::OptionalExtension;
        Ok(self
            .conn()?
            .query_row(Q_USER_HASH, params![t.name(), user], |r| r.get(0))
            .optional()?
            .flatten())
    }

    /// Records an app password (only its HMAC digest is stored).
    pub fn token_add(&self, t: &TenantCtx, token_id: &str, user: &str, mac: &[u8; 32], label: &str) -> Result<()> {
        self.conn()?
            .execute(Q_TOKEN_ADD, params![t.name(), token_id, user, &mac[..], label, now()])?;
        Ok(())
    }

    /// Records an app password waiting for its first use (QR code): it no longer expires once used, and is gone at
    /// `until` otherwise. Replaces the user's other passwords still waiting (a new QR code cancels the previous one).
    pub fn token_add_pending(
        &self,
        t: &TenantCtx,
        (token_id, user): (&str, &str),
        mac: &[u8; 32],
        label: &str,
        until: i64,
    ) -> Result<()> {
        let c = self.conn()?;
        let tx = c.unchecked_transaction()?;
        tx.execute(Q_TOKEN_PENDING_DEL, params![t.name(), user])?;
        tx.execute(
            Q_TOKEN_ADD_PENDING,
            params![t.name(), token_id, user, &mac[..], label, now(), until],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The user's app passwords; those that expired unused are deleted first.
    pub fn token_list(&self, t: &TenantCtx, user: &str) -> Result<Vec<TokenRow>> {
        let conn = self.conn()?;
        conn.execute(Q_TOKEN_EXPIRED_DEL, params![t.name(), now()])?;
        let mut st = conn.prepare(Q_TOKEN_LIST)?;
        let rows = st.query_map(params![t.name(), user], |r| {
            Ok(TokenRow {
                token_id: r.get(0)?,
                label: r.get(1)?,
                created_at: r.get(2)?,
                last_used_at: r.get(3)?,
                expires_at: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn token_delete(&self, t: &TenantCtx, user: &str, token_id: &str) -> Result<bool> {
        Ok(self.conn()?.execute(Q_TOKEN_DEL, params![t.name(), user, token_id])? == 1)
    }

    pub fn session_add(&self, t: &TenantCtx, user: &str, mac: &[u8; 32], ttl_secs: i64) -> Result<()> {
        self.session_add_as(t, user, mac, ttl_secs, false)
    }

    /// `pending`: the password is right, the second step is still to come (the session opens nothing else).
    pub fn session_add_as(
        &self,
        t: &TenantCtx,
        user: &str,
        mac: &[u8; 32],
        ttl_secs: i64,
        pending: bool,
    ) -> Result<()> {
        let c = self.conn()?;
        c.execute(Q_SESSION_PURGE, params![t.name(), now()])?;
        c.execute(
            Q_SESSION_ADD,
            params![
                t.name(),
                crate::auth::random_hex::<16>()?,
                user,
                &mac[..],
                now(),
                now() + ttl_secs,
                i64::from(pending)
            ],
        )?;
        Ok(())
    }

    /// The session's account and its state; `None`: unknown, expired, or account disabled.
    pub fn session_user(&self, t: &TenantCtx, mac: &[u8; 32]) -> Result<Option<SessionRow>> {
        use rusqlite::OptionalExtension;
        Ok(self
            .conn()?
            .query_row(Q_SESSION_USER, params![t.name(), &mac[..], now()], |r| {
                Ok(SessionRow {
                    user: r.get(0)?,
                    must_change: r.get::<_, i64>(1)? != 0,
                    pending: r.get::<_, i64>(2)? != 0,
                    totp: r.get::<_, i64>(3)? != 0,
                    has_password: r.get::<_, i64>(4)? != 0,
                    created: r.get(5)?,
                })
            })
            .optional()?)
    }

    /// Sealed TOTP secret (`None`: off) and last step used, of an active account; `None`: unknown or disabled.
    pub fn totp_get(&self, t: &TenantCtx, user: &str) -> Result<Option<(Option<Vec<u8>>, u64)>> {
        use rusqlite::OptionalExtension;
        Ok(self
            .conn()?
            .query_row(Q_TOTP_GET, params![t.name(), user], |r| {
                Ok((r.get(0)?, u64::try_from(r.get::<_, i64>(1)?).unwrap_or(0)))
            })
            .optional()?)
    }

    /// Turns two-step verification on (or replaces it): sealed secret, step just used, recovery code digests (the old
    /// ones are dropped), in one transaction. `false`: unknown account.
    pub fn totp_enable(&self, t: &TenantCtx, user: &str, sealed: &[u8], last: u64, codes: &[[u8; 32]]) -> Result<bool> {
        let c = self.conn()?;
        let tx = c.unchecked_transaction()?;
        let last = i64::try_from(last).unwrap_or(i64::MAX);
        let found = tx.execute(Q_TOTP_SET, params![t.name(), user, sealed, last])? == 1;
        tx.execute(Q_RECOVERY_DEL_ALL, params![t.name(), user])?;
        for m in codes {
            tx.execute(Q_RECOVERY_ADD, params![t.name(), user, &m[..]])?;
        }
        tx.commit()?;
        Ok(found)
    }

    /// Turns two-step verification off: secret and recovery codes gone. `false`: unknown account.
    pub fn totp_disable(&self, t: &TenantCtx, user: &str) -> Result<bool> {
        let c = self.conn()?;
        let tx = c.unchecked_transaction()?;
        let found = tx.execute(Q_TOTP_SET, params![t.name(), user, None::<Vec<u8>>, 0])? == 1;
        tx.execute(Q_RECOVERY_DEL_ALL, params![t.name(), user])?;
        tx.commit()?;
        Ok(found)
    }

    /// Records the use of time step `step`; `false` if a step as new or newer was already used (replay).
    pub fn totp_use(&self, t: &TenantCtx, user: &str, step: u64) -> Result<bool> {
        let step = i64::try_from(step).unwrap_or(i64::MAX);
        Ok(self.conn()?.execute(Q_TOTP_USE, params![t.name(), user, step])? == 1)
    }

    /// New recovery codes (digests), the old ones dropped.
    pub fn recovery_replace(&self, t: &TenantCtx, user: &str, codes: &[[u8; 32]]) -> Result<()> {
        let c = self.conn()?;
        let tx = c.unchecked_transaction()?;
        tx.execute(Q_RECOVERY_DEL_ALL, params![t.name(), user])?;
        for m in codes {
            tx.execute(Q_RECOVERY_ADD, params![t.name(), user, &m[..]])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Uses a recovery code (gone once used); `false`: unknown, already used, or two-step verification off.
    pub fn recovery_use(&self, t: &TenantCtx, user: &str, mac: &[u8; 32]) -> Result<bool> {
        Ok(self
            .conn()?
            .execute(Q_RECOVERY_USE, params![t.name(), user, &mac[..]])?
            == 1)
    }

    pub fn recovery_count(&self, t: &TenantCtx, user: &str) -> Result<u32> {
        Ok(self
            .conn()?
            .query_row(Q_RECOVERY_COUNT, params![t.name(), user], |r| r.get(0))?)
    }

    /// Tests: makes the database fail on purpose (a trigger that refuses, a table moved away).
    #[cfg(test)]
    pub(crate) fn exec_for_test(&self, sql: &str) {
        self.conn().unwrap().execute_batch(sql).unwrap();
    }

    /// Tests: forget the last step used, so that a test can sign in more than three times in 30 seconds.
    #[cfg(test)]
    pub(crate) fn totp_rewind(&self, t: &TenantCtx, user: &str) {
        let q = "UPDATE user SET totp_last = 0 WHERE tenant_id = ?1 AND user_id = ?2";
        self.conn().unwrap().execute(q, params![t.name(), user]).unwrap();
    }

    /// Ends every web session of the account but the one with digest `keep`.
    pub fn session_delete_others(&self, t: &TenantCtx, user: &str, keep: &[u8; 32]) -> Result<()> {
        self.conn()?
            .execute(Q_SESSION_DEL_OTHERS, params![t.name(), user, &keep[..]])?;
        Ok(())
    }

    /// Ends every web session of the account.
    pub fn session_delete_user(&self, t: &TenantCtx, user: &str) -> Result<()> {
        self.conn()?.execute(Q_SESSION_DEL_USER, params![t.name(), user])?;
        Ok(())
    }

    pub fn session_delete(&self, t: &TenantCtx, mac: &[u8; 32]) -> Result<()> {
        self.conn()?.execute(Q_SESSION_DEL, params![t.name(), &mac[..]])?;
        Ok(())
    }

    /// Adds a link, and writes its creation in the link history.
    pub fn share_add(&self, t: &TenantCtx, s: &NewShare<'_>) -> Result<()> {
        self.conn()?.execute(
            Q_SHARE_ADD,
            params![
                t.name(),
                s.share_id,
                s.user,
                &s.mac[..],
                s.fileid,
                s.path_hint,
                s.perms,
                s.password_hash,
                s.expires_at,
                s.max_downloads,
                now(),
                s.opts.upload,
                s.opts.label,
                s.opts.note,
                s.opts.hide_download
            ],
        )?;
        self.share_event(t, s.share_id, s.user, ShareEventKind::Created, "", 0)
    }

    pub fn share_by_mac(&self, t: &TenantCtx, mac: &[u8; 32]) -> Result<Option<ShareRow>> {
        use rusqlite::OptionalExtension;
        Ok(self
            .conn()?
            .query_row(Q_SHARE_BY_MAC, params![t.name(), &mac[..]], share_row)
            .optional()?)
    }

    /// `user`'s still usable links: neither revoked, nor expired, nor exhausted.
    pub fn share_list(&self, t: &TenantCtx, user: &str) -> Result<Vec<ShareRow>> {
        let conn = self.conn()?;
        let mut st = conn.prepare(Q_SHARE_LIST)?;
        let rows = st.query_map(params![t.name(), user, now()], share_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Revokes one of `user`'s live links, and writes it in the link history.
    pub fn share_revoke(&self, t: &TenantCtx, user: &str, share_id: &str) -> Result<bool> {
        let done = self
            .conn()?
            .execute(Q_SHARE_REVOKE, params![t.name(), user, share_id, now()])?
            == 1;
        if done {
            self.share_event(t, share_id, user, ShareEventKind::Revoked, "", 0)?;
        }
        Ok(done)
    }

    /// Changes a live link (the token stays): access, password digest, expiry, options.
    #[allow(clippy::too_many_arguments)]
    pub fn share_update(
        &self,
        t: &TenantCtx,
        user: &str,
        share_id: &str,
        perms: &str,
        password_hash: Option<&str>,
        expires_at: Option<i64>,
        opts: &LinkOptions,
    ) -> Result<bool> {
        let o = opts;
        Ok(self.conn()?.execute(
            Q_SHARE_UPDATE,
            params![
                t.name(),
                user,
                share_id,
                perms,
                password_hash,
                expires_at,
                o.upload,
                o.label,
                o.note,
                o.hide_download
            ],
        )? == 1)
    }

    /// Suspends a link whose target is in the trash.
    pub fn share_suspend(&self, t: &TenantCtx, share_id: &str) -> Result<()> {
        self.conn()?.execute(Q_SHARE_SUSPEND, params![t.name(), share_id])?;
        Ok(())
    }

    /// Resumes a suspended link whose target was restored.
    pub fn share_resume(&self, t: &TenantCtx, share_id: &str) -> Result<()> {
        self.conn()?.execute(Q_SHARE_RESUME, params![t.name(), share_id])?;
        Ok(())
    }

    /// `user`'s suspended links (target in the trash), to check again.
    pub fn share_suspended(&self, t: &TenantCtx, user: &str) -> Result<Vec<ShareRow>> {
        let conn = self.conn()?;
        let mut st = conn.prepare(Q_SHARE_SUSPENDED)?;
        let rows = st.query_map(params![t.name(), user], share_row)?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// End of a link whose target is gone (deleted, moved or renamed); no effect if it is already revoked.
    pub fn share_gone(&self, t: &TenantCtx, share_id: &str) -> Result<()> {
        self.conn()?.execute(Q_SHARE_GONE, params![t.name(), share_id, now()])?;
        Ok(())
    }

    /// Counts a download; false if the limit is reached (checked in the same query).
    pub fn share_hit(&self, t: &TenantCtx, share_id: &str) -> Result<bool> {
        Ok(self.conn()?.execute(Q_SHARE_HIT, params![t.name(), share_id, now()])? == 1)
    }

    pub fn share_seen(&self, t: &TenantCtx, share_id: &str) -> Result<()> {
        self.conn()?.execute(Q_SHARE_SEEN, params![t.name(), share_id, now()])?;
        Ok(())
    }

    /// Records a link event (grouped with the previous one if it extends it, see `EVENT_GROUP_SECS`). `owner`:
    /// the link's owner. Retention is applied by `share_events_purge` (hourly task).
    pub fn share_event(
        &self,
        t: &TenantCtx,
        share_id: &str,
        owner: &str,
        kind: ShareEventKind,
        path: &str,
        bytes: i64,
    ) -> Result<()> {
        use rusqlite::OptionalExtension;
        let conn = self.conn()?;
        let now = now();
        let last: Option<(i64, String, String, i64)> = conn
            .query_row(Q_EVENT_LAST, params![t.name(), share_id], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .optional()?;
        if let Some((id, k, p, at)) = last
            && k == kind.as_str()
            && now - at <= EVENT_GROUP_SECS
            && (matches!(kind, ShareEventKind::Drop | ShareEventKind::Denied) || p == path)
        {
            conn.execute(Q_EVENT_BUMP, params![t.name(), id, bytes, now])?;
            return Ok(());
        }
        conn.execute(
            Q_EVENT_ADD,
            params![t.name(), share_id, owner, now, kind.as_str(), path, bytes],
        )?;
        Ok(())
    }

    /// Purge of the whole tenant's history: older than `keep_days`, and beyond `EVENTS_MAX` per user.
    /// Returns the number of events deleted.
    pub fn share_events_purge(&self, t: &TenantCtx, keep_days: u32) -> Result<usize> {
        let since = now() - i64::from(keep_days) * 86_400;
        Ok(self
            .conn()?
            .execute(Q_EVENT_PURGE, params![t.name(), since, EVENTS_MAX])?)
    }

    /// `user`'s link history, newest to oldest, within the retention period; empty `share_id` =
    /// every link. Returns (page, total count).
    pub fn share_events(
        &self,
        t: &TenantCtx,
        user: &str,
        share_id: &str,
        keep_days: u32,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<ShareEvent>, i64)> {
        self.events(t, user, (share_id, false), keep_days, limit, offset)
    }

    /// What the visitors did (not the owner's own creations and revocations): the "Recent activity" box.
    pub fn guest_events(&self, t: &TenantCtx, user: &str, keep_days: u32, limit: u32) -> Result<Vec<ShareEvent>> {
        Ok(self.events(t, user, ("", true), keep_days, limit, 0)?.0)
    }

    /// `(share_id, guests_only)`: one link ("" = all), visitors' events only.
    fn events(
        &self,
        t: &TenantCtx,
        user: &str,
        (share_id, guests): (&str, bool),
        keep_days: u32,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<ShareEvent>, i64)> {
        let conn = self.conn()?;
        let now = now();
        let since = now - i64::from(keep_days) * 86_400;
        let total: i64 = conn.query_row(Q_EVENT_COUNT, params![t.name(), user, share_id, since, guests], |r| {
            r.get(0)
        })?;
        let mut st = conn.prepare(Q_EVENT_LIST)?;
        let rows = st.query_map(params![t.name(), user, share_id, since, limit, offset, guests], |r| {
            Ok(ShareEvent {
                share_id: r.get(0)?,
                at: r.get(1)?,
                kind: ShareEventKind::parse(&r.get::<_, String>(2)?),
                path: r.get(3)?,
                count: r.get(4)?,
                bytes: r.get(5)?,
                share_path: r.get(6)?,
                share_end: share_end(r, 7, now)?,
            })
        })?;
        Ok((rows.collect::<rusqlite::Result<_>>()?, total))
    }

    /// `user`'s links that have history within the retention period (revoked ones included).
    pub fn event_shares(&self, t: &TenantCtx, user: &str, keep_days: u32) -> Result<Vec<EventShare>> {
        let conn = self.conn()?;
        let now = now();
        let since = now - i64::from(keep_days) * 86_400;
        let mut st = conn.prepare(Q_EVENT_SHARES)?;
        let rows = st.query_map(params![t.name(), user, since], |r| {
            Ok(EventShare {
                share_id: r.get(0)?,
                path_hint: r.get(1)?,
                end: share_end(r, 2, now)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Gives back the file and the `bytes` reserved by `share_drop` for a drop that did not complete.
    pub fn share_drop_release(&self, t: &TenantCtx, share_id: &str, bytes: i64) -> Result<()> {
        self.conn()?
            .execute(Q_SHARE_DROP_RELEASE, params![t.name(), share_id, bytes])?;
        Ok(())
    }

    /// Reserves one file and `bytes` on a drop link; false if `max_bytes` or `max_files` would be exceeded.
    pub fn share_drop(
        &self,
        t: &TenantCtx,
        share_id: &str,
        bytes: i64,
        max_bytes: i64,
        max_files: i64,
    ) -> Result<bool> {
        Ok(self
            .conn()?
            .execute(Q_SHARE_DROP, params![t.name(), share_id, bytes, max_bytes, max_files])?
            == 1)
    }

    /// Owner (active account) of the token with digest `mac` if it is valid; records its last use, at most
    /// one write per hour and per token (a WebDAV request must not cost a database write).
    pub fn token_user(&self, t: &TenantCtx, mac: &[u8; 32]) -> Result<Option<String>> {
        use rusqlite::OptionalExtension;
        let conn = self.conn()?;
        let now = now();
        let row: Option<(String, Option<i64>, Option<i64>)> = conn
            .query_row(Q_TOKEN_USER, params![t.name(), &mac[..], now], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?;
        let Some((user, seen, expires)) = row else {
            return Ok(None);
        };
        // First use of a password waiting for it (QR code): it is kept from now on.
        if expires.is_some() {
            conn.execute(Q_TOKEN_KEEP, params![t.name(), &mac[..], now])?;
            return Ok(Some(user));
        }
        if seen.is_none_or(|s| now - s >= TOKEN_SEEN_EVERY)
            && let Err(e) = conn.execute(Q_TOKEN_SEEN, params![t.name(), &mac[..], now])
        {
            tracing::warn!(tenant = t.name(), "token last use not recorded: {e}");
        }
        Ok(Some(user))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenant::tests::two_tenants;

    #[test]
    fn every_query_filters_by_tenant() {
        for q in QUERIES {
            assert!(q.contains("tenant_id"), "query without tenant_id: {q}");
        }
    }

    #[test]
    fn every_table_has_tenant_in_primary_key() {
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("app.db")).unwrap();
        let conn = db.conn().unwrap();
        let mut st = conn
            .prepare("SELECT name FROM sqlite_schema WHERE type = 'table'")
            .unwrap();
        let tables: Vec<String> = st.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect();
        assert!(tables.len() >= 6);
        for t in tables {
            let pk: Vec<String> = conn
                .prepare(&format!("SELECT name FROM pragma_table_info('{t}') WHERE pk > 0"))
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            assert!(
                pk.iter().any(|c| c == "tenant_id"),
                "table {t}: tenant_id missing from the primary key"
            );
        }
    }

    /// Link history: grouping (same file, drops of one upload, password attempts), filter by link,
    /// survival after revocation, retention, cap, cascade delete with the link, tenant isolation.
    #[test]
    fn share_events_grouped_bounded_and_isolated() {
        use ShareEventKind::*;
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("app.db")).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let (a, b) = (reg.by_name("alpha").unwrap(), reg.by_name("beta").unwrap());
        db.user_add(&a, "alice", "h", true).unwrap();
        db.user_add(&b, "alice", "h", false).unwrap();
        let add = |t: &TenantCtx, id: &str, mac: u8| {
            db.share_add(
                t,
                &NewShare {
                    share_id: id,
                    user: "alice",
                    mac: &[mac; 32],
                    fileid: &[1],
                    path_hint: "Docs",
                    perms: "read",
                    password_hash: None,
                    expires_at: None,
                    max_downloads: None,
                    opts: &Default::default(),
                },
            )
            .unwrap()
        };
        add(&a, "s1", 1);
        add(&a, "s2", 2);
        add(&b, "s1", 3); // same identifier, other tenant
        let ev = |t: &TenantCtx, s: &str, k, p: &str, n| db.share_event(t, s, "alice", k, p, n).unwrap();
        ev(&a, "s1", Download, "x.pdf", 0);
        ev(&a, "s1", Download, "x.pdf", 0); // same file: grouped
        ev(&a, "s1", Download, "y.pdf", 0);
        ev(&a, "s2", Drop, "a.jpg", 10);
        ev(&a, "s2", Drop, "b.jpg", 20); // same drop: grouped, sizes added up
        for _ in 0..3 {
            ev(&a, "s1", Denied, "", 0);
        }
        ev(&b, "s1", Zip, "Docs", 0);

        let list = |t: &TenantCtx, s: &str| db.share_events(t, "alice", s, 365, 50, 0).unwrap();
        // The owner's creations are in the history, not in what the visitors did.
        let (with_owner, n) = list(&a, "");
        assert_eq!((n, with_owner.iter().filter(|e| e.kind == Created).count()), (6, 2));
        let all = db.guest_events(&a, "alice", 365, 50).unwrap();
        let got: Vec<_> = all
            .iter()
            .map(|e| (e.kind, e.path.as_str(), e.count, e.bytes))
            .collect();
        assert_eq!(
            got,
            [
                (Denied, "", 3, 0),
                (Drop, "a.jpg", 2, 30),
                (Download, "y.pdf", 1, 0),
                (Download, "x.pdf", 2, 0)
            ]
        );
        let (only, n) = list(&a, "s2");
        assert_eq!((only.len(), n, only[0].kind), (2, 2, Drop));
        let (beta, _) = list(&b, "");
        assert_eq!((beta.len(), beta[0].kind), (2, Zip));
        // Revocation: written once, in the history of that link only.
        assert!(db.share_revoke(&a, "alice", "s2").unwrap() && !db.share_revoke(&a, "alice", "s2").unwrap());
        let (s2, _) = list(&a, "s2");
        assert_eq!(s2.iter().map(|e| e.kind).collect::<Vec<_>>(), [Revoked, Drop, Created]);
        assert_eq!(db.share_events(&a, "alice", "", 365, 2, 2).unwrap().0.len(), 2); // pagination
        let shares: Vec<_> = db
            .event_shares(&a, "alice", 365)
            .unwrap()
            .into_iter()
            .map(|s| s.share_id)
            .collect();
        assert_eq!(shares, ["s1", "s2"]);

        // Revoked: the history stays, flagged.
        assert!(db.share_revoke(&a, "alice", "s1").unwrap());
        assert!(list(&a, "s1").0.iter().all(|e| e.share_end == Some(ShareEnd::Revoked)));

        // Retention: an event that is too old is no longer shown, then deleted by the hourly purge.
        let raw = |q: &str| db.conn().unwrap().execute(q, []).unwrap();
        raw("UPDATE share_event SET at = at - 400 * 86400 WHERE tenant_id = 'alpha' AND path = 'x.pdf'");
        assert_eq!(list(&a, "").1, 7); // 2 created, 2 revoked, y.pdf, the drop group, the refused passwords
        let left = |q: &str| -> i64 { db.conn().unwrap().query_row(q, [], |r| r.get(0)).unwrap() };
        assert_eq!(db.share_events_purge(&a, 365).unwrap(), 1);
        assert_eq!(left("SELECT count(*) FROM share_event WHERE path = 'x.pdf'"), 0);

        // Per-user cap, whatever the mix of writes between the tenant's users: each one keeps
        // exactly its EVENTS_MAX newest.
        db.user_add(&a, "bob", "h", false).unwrap();
        db.share_add(
            &a,
            &NewShare {
                share_id: "b1",
                user: "bob",
                mac: &[9; 32],
                fileid: &[1],
                path_hint: "Docs",
                perms: "read",
                password_hash: None,
                expires_at: None,
                max_downloads: None,
                opts: &Default::default(),
            },
        )
        .unwrap();
        for i in 0..EVENTS_MAX + 30 {
            ev(&a, "s2", Download, &format!("g{i}"), 0);
            db.share_event(&a, "b1", "bob", Download, &format!("h{i}"), 0).unwrap();
        }
        let per = |u: &str| {
            left(&format!(
                "SELECT count(*) FROM share_event WHERE tenant_id = 'alpha' AND user_id = '{u}'"
            ))
        };
        assert!(per("alice") > EVENTS_MAX && per("bob") > EVENTS_MAX);
        db.share_events_purge(&a, 365).unwrap();
        assert_eq!((per("alice"), per("bob")), (EVENTS_MAX, EVENTS_MAX));
        assert_eq!(
            left(&format!(
                "SELECT count(*) FROM share_event WHERE path = 'g{}'",
                EVENTS_MAX + 29
            )),
            1
        );
        assert_eq!(left("SELECT count(*) FROM share_event WHERE path = 'g0'"), 0); // the oldest go
        assert_eq!(list(&b, "").0.len(), 2); // the other tenant is not touched by the purge (created, zip)

        // Link deleted (account deleted): its events go with it.
        raw("DELETE FROM share WHERE tenant_id = 'alpha' AND share_id = 's2'");
        assert_eq!(
            left("SELECT count(*) FROM share_event WHERE tenant_id = 'alpha' AND share_id = 's2'"),
            0
        );
    }

    /// The link list only shows those that still serve; the history says why the others ended.
    #[test]
    fn share_list_only_usable_and_end_reasons() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("app.db")).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let a = reg.by_name("alpha").unwrap();
        db.user_add(&a, "alice", "h", true).unwrap();
        let now = now();
        let add = |id: &str, mac: u8, expires: Option<i64>, max: Option<i64>| {
            db.share_add(
                &a,
                &NewShare {
                    share_id: id,
                    user: "alice",
                    mac: &[mac; 32],
                    fileid: &[1],
                    path_hint: id,
                    perms: "read",
                    password_hash: None,
                    expires_at: expires,
                    max_downloads: max,
                    opts: &Default::default(),
                },
            )
            .unwrap();
            db.share_event(&a, id, "alice", ShareEventKind::Download, "f", 0)
                .unwrap();
        };
        add("actif", 1, Some(now + 3600), Some(2));
        add("expire", 2, Some(now - 1), None);
        add("epuise", 3, None, Some(1));
        add("revoque", 4, None, None);
        add("disparu", 5, None, None);
        add("suspendu", 6, None, None);
        db.share_suspend(&a, "suspendu").unwrap();
        assert!(db.share_hit(&a, "epuise").unwrap());
        assert!(!db.share_hit(&a, "epuise").unwrap()); // limit reached
        db.share_revoke(&a, "alice", "revoque").unwrap();
        db.share_gone(&a, "disparu").unwrap();
        db.share_gone(&a, "revoque").unwrap(); // already revoked: stays "revoked"

        let ids: Vec<_> = db
            .share_list(&a, "alice")
            .unwrap()
            .into_iter()
            .map(|s| s.share_id)
            .collect();
        assert_eq!(ids, ["actif"]);
        let mut ends: Vec<_> = db
            .event_shares(&a, "alice", 365)
            .unwrap()
            .into_iter()
            .map(|s| (s.share_id, s.end))
            .collect();
        ends.sort_by(|x, y| x.0.cmp(&y.0));
        assert_eq!(
            ends,
            [
                ("actif".into(), None),
                ("disparu".into(), Some(ShareEnd::Gone)),
                ("epuise".into(), Some(ShareEnd::Exhausted)),
                ("expire".into(), Some(ShareEnd::Expired)),
                ("revoque".into(), Some(ShareEnd::Revoked)),
                ("suspendu".into(), Some(ShareEnd::Suspended)),
            ]
        );
        let susp: Vec<_> = db
            .share_suspended(&a, "alice")
            .unwrap()
            .into_iter()
            .map(|s| (s.share_id, s.suspended))
            .collect();
        assert_eq!(susp, [("suspendu".to_owned(), true)]);
        db.share_suspend(&a, "revoque").unwrap(); // revoked: neither suspended nor resumed
        db.share_resume(&a, "suspendu").unwrap();
        let mut ids: Vec<_> = db
            .share_list(&a, "alice")
            .unwrap()
            .into_iter()
            .map(|s| s.share_id)
            .collect();
        ids.sort();
        assert_eq!(ids, ["actif", "suspendu"]);
        assert!(db.share_suspended(&a, "alice").unwrap().is_empty());
        assert_eq!(ShareEnd::Gone.label(), "deleted or moved target");
    }

    /// Upgrade of a database made before the last migration: its accounts keep their own password and have no two-step
    /// verification, a backup is made; an account added afterwards must change its password.
    #[test]
    fn upgrade_keeps_existing_passwords() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("app.db");
        {
            let c = Connection::open(&path).unwrap();
            let before = MIGRATIONS.len() - 3; // before `must_change`, two-step verification and OIDC
            for sql in &MIGRATIONS[..before] {
                c.execute_batch(sql).unwrap();
            }
            c.pragma_update(None, "user_version", i64::try_from(before).unwrap())
                .unwrap();
            c.execute_batch(
                "INSERT INTO tenant (tenant_id, created_at) VALUES ('alpha', 0);
                 INSERT INTO user (tenant_id, user_id, password_hash, role, created_at) VALUES ('alpha', 'alice', 'h', 'user', 0);
                 INSERT INTO session (tenant_id, session_id, user_id, mac, created_at, expires_at)
                     VALUES ('alpha', 's', 'alice', x'0101010101010101010101010101010101010101010101010101010101010101', 0, 9999999999);",
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let a = reg.by_name("alpha").unwrap();
        assert_eq!(db.user_must_change(&a, "alice").unwrap(), Some(false));
        assert_eq!(db.totp_get(&a, "alice").unwrap(), Some((None, 0))); // two-step verification off
        assert_eq!(db.recovery_count(&a, "alice").unwrap(), 0);
        let row = db.session_user(&a, &[1; 32]).unwrap().unwrap(); // an open session stays open, not waiting a code
        assert!(!row.pending && !row.must_change && !row.totp);
        db.user_add(&a, "bob", "h", false).unwrap();
        assert_eq!(db.user_must_change(&a, "bob").unwrap(), Some(true));
        let backups = std::fs::read_dir(d.path())
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().ends_with(".bak"))
            .count();
        assert_eq!(backups, 1);
    }

    /// Single sign-on: an identity is bound to one account of one tenant. Same `sub` on two accounts of a tenant is
    /// refused and the first link stays; the same `sub` on another tenant is a different account; a relink is refused;
    /// a disabled account is not found. Each link ends that account's sessions only, and writes an `audit` row.
    #[test]
    fn oidc_link_binds_one_identity() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("app.db")).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let (a, b) = (reg.by_name("alpha").unwrap(), reg.by_name("beta").unwrap());
        for (t, u) in [(&a, "alice"), (&a, "bob"), (&b, "alice")] {
            db.user_add_oidc(t, u, false).unwrap();
        }
        let iss = "https://auth.example";
        db.user_oidc_link(&a, "alice", iss, "sub-alice").unwrap();
        assert_eq!(db.user_by_oidc(&a, iss, "sub-alice").unwrap().as_deref(), Some("alice"));
        assert_eq!(db.user_by_oidc(&a, iss, "sub-bob").unwrap(), None);
        // Another issuer or another subject: no match.
        assert_eq!(db.user_by_oidc(&a, "https://other.example", "sub-alice").unwrap(), None);
        assert_eq!(db.user_by_oidc(&a, iss, "sub-alice ").unwrap(), None);
        // Same identity on a second account of the same tenant: refused, first link intact.
        assert!(db.user_oidc_link(&a, "bob", iss, "sub-alice").is_err());
        assert_eq!(db.user_by_oidc(&a, iss, "sub-alice").unwrap().as_deref(), Some("alice"));
        assert_eq!(db.user_by_oidc(&a, iss, "sub-bob").unwrap(), None);
        // The same `sub` in the other tenant is another account (§9).
        db.user_oidc_link(&b, "alice", iss, "sub-alice").unwrap();
        assert_eq!(db.user_by_oidc(&b, iss, "sub-alice").unwrap().as_deref(), Some("alice"));
        // Relink refused, and an unknown or disabled account is not found.
        assert!(db.user_oidc_link(&a, "alice", iss, "sub-other").is_err());
        assert!(db.user_oidc_link(&a, "nobody", iss, "sub-x").is_err());
        db.user_set_active(&a, "bob", false).unwrap();
        assert!(db.user_oidc_link(&a, "bob", iss, "sub-bob").is_err());
        db.user_set_active(&a, "bob", true).unwrap();
        db.user_oidc_link(&a, "bob", iss, "sub-bob").unwrap();
        assert_eq!(db.user_by_oidc(&a, iss, "sub-bob").unwrap().as_deref(), Some("bob"));
        // A disabled account's identity is not found either.
        db.user_set_active(&a, "bob", false).unwrap();
        assert_eq!(db.user_by_oidc(&a, iss, "sub-bob").unwrap(), None);
        let audits: Vec<_> = db.audit_list(&a).unwrap().into_iter().map(|r| r.action).collect();
        assert_eq!(audits, ["oidc-link", "oidc-link"]);
    }

    /// Linking is one transaction: the account loses its password and must-change flag, ends its sessions, keeps its
    /// TOTP secret and recovery codes; other accounts and the other tenant are untouched.
    #[test]
    fn oidc_link_ends_that_account_only() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("app.db")).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let (a, b) = (reg.by_name("alpha").unwrap(), reg.by_name("beta").unwrap());
        for (t, u) in [(&a, "alice"), (&a, "bob"), (&b, "alice")] {
            db.user_add(t, u, "h", false).unwrap();
        }
        db.totp_enable(&a, "alice", &[7; 32], 5, &[[9; 32], [8; 32]]).unwrap();
        let mac = |i: u8| [i; 32];
        for (t, u, i) in [(&a, "alice", 1), (&a, "bob", 2), (&b, "alice", 3)] {
            db.session_add(t, u, &mac(i), 600).unwrap();
        }
        db.user_oidc_link(&a, "alice", "https://auth.example", "sub-alice")
            .unwrap();
        assert_eq!(
            db.user_by_oidc(&a, "https://auth.example", "sub-alice")
                .unwrap()
                .as_deref(),
            Some("alice")
        );
        // No password any more (and nothing to change), the identity is the only way in.
        assert_eq!(db.user_password_hash(&a, "alice").unwrap(), None);
        assert_eq!(db.user_must_change(&a, "alice").unwrap(), Some(false));
        // TOTP and recovery codes kept: the tenant may switch the second factor back later.
        assert_eq!(db.totp_get(&a, "alice").unwrap(), Some((Some(vec![7; 32]), 5)));
        assert_eq!(db.recovery_count(&a, "alice").unwrap(), 2);
        // Sessions: that account only.
        assert_eq!(db.session_user(&a, &mac(1)).unwrap(), None);
        assert!(db.session_user(&a, &mac(2)).unwrap().is_some());
        assert!(db.session_user(&b, &mac(3)).unwrap().is_some());
    }

    /// `user passwd` on a linked account (the recovery procedure): the identity goes, a password comes back and the
    /// user chooses their own at the next sign-in; sessions end; the `audit` table records it. The old `sub` no longer
    /// matches. An account that is not linked is left alone by the unlink path.
    #[test]
    fn oidc_unlink_restores_a_password() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("app.db")).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let a = reg.by_name("alpha").unwrap();
        db.user_add_oidc(&a, "alice", false).unwrap();
        let iss = "https://auth.example";
        db.user_oidc_link(&a, "alice", iss, "sub-alice").unwrap();
        db.session_add(&a, "alice", &[1; 32], 600).unwrap();
        assert!(db.user_oidc_unlink_with_password(&a, "alice", "newhash").unwrap());
        assert_eq!(db.user_password_hash(&a, "alice").unwrap().as_deref(), Some("newhash"));
        assert_eq!(db.user_must_change(&a, "alice").unwrap(), Some(true));
        assert_eq!(db.user_by_oidc(&a, iss, "sub-alice").unwrap(), None);
        assert_eq!(db.session_user(&a, &[1; 32]).unwrap(), None);
        // A second call refuses: the account is no longer linked.
        assert!(!db.user_oidc_unlink_with_password(&a, "alice", "other").unwrap());
        assert_eq!(db.user_password_hash(&a, "alice").unwrap().as_deref(), Some("newhash"));
        let actions: Vec<_> = db.audit_list(&a).unwrap().into_iter().map(|r| r.action).collect();
        assert_eq!(actions, ["oidc-link", "oidc-unlink"]);
    }

    /// The session tells whether the account is linked and when it was created (freshness of the login).
    #[test]
    fn session_reports_linked_and_age() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("app.db")).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let a = reg.by_name("alpha").unwrap();
        db.user_add(&a, "alice", "h", false).unwrap();
        db.user_add_oidc(&a, "bob", false).unwrap();
        db.user_oidc_link(&a, "bob", "https://auth.example", "sub-bob").unwrap();
        db.session_add(&a, "alice", &[1; 32], 600).unwrap();
        db.session_add(&a, "bob", &[2; 32], 600).unwrap();
        for (mac, user) in [([1; 32], "alice"), ([2; 32], "bob")] {
            assert_eq!(db.session_user(&a, &mac).unwrap().unwrap().user, user);
        }
    }

    /// An account for provider sign-in exists once: a second attempt in the same tenant says so, and the same name
    /// stays free in the other tenant.
    #[test]
    fn user_add_oidc_exists_once() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("app.db")).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let a = reg.by_name("alpha").unwrap();
        db.user_add_oidc(&a, "bob", false).unwrap();
        let e = db.user_add_oidc(&a, "bob", false).unwrap_err().to_string();
        assert!(e.contains("already exists"), "{e}");
        db.user_add_oidc(&reg.by_name("beta").unwrap(), "bob", false).unwrap();
    }

    /// A database made before the single sign-on migration keeps its accounts: no identity, password unchanged.
    #[test]
    fn upgrade_adds_oidc_columns() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("app.db");
        {
            let c = Connection::open(&path).unwrap();
            let before = MIGRATIONS.len() - 1;
            for sql in &MIGRATIONS[..before] {
                c.execute_batch(sql).unwrap();
            }
            c.pragma_update(None, "user_version", i64::try_from(before).unwrap())
                .unwrap();
            c.execute_batch(
                "INSERT INTO tenant (tenant_id, created_at) VALUES ('alpha', 0);
                 INSERT INTO user (tenant_id, user_id, password_hash, role, created_at, must_change)
                     VALUES ('alpha', 'alice', 'h', 'user', 0, 1);",
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let a = reg.by_name("alpha").unwrap();
        assert_eq!(db.user_password_hash(&a, "alice").unwrap().as_deref(), Some("h"));
        assert_eq!(db.user_by_oidc(&a, "https://auth.example", "sub-alice").unwrap(), None);
        // The unique index is in place: the same identity cannot be bound twice in one tenant.
        db.user_add_oidc(&a, "bob", false).unwrap();
        db.user_oidc_link(&a, "alice", "https://auth.example", "s").unwrap();
        assert!(db.user_oidc_link(&a, "bob", "https://auth.example", "s").is_err());
    }

    /// Model test of the account state machine (proptest): random adds, links, password recoveries, disabling and
    /// enabling, on two tenants, each refused step ignored. After every class of step: no account has a password and
    /// an identity together, and a `(tenant, issuer, subject)` maps to at most one account.
    #[test]
    fn accounts_model() {
        use proptest::prelude::*;
        use proptest::test_runner::{Config as PropConfig, TestRunner};

        #[derive(Clone, Debug)]
        enum Op {
            /// (tenant, name, oidc)
            Add(usize, usize, bool),
            /// (tenant, name, subject)
            Link(usize, usize, usize),
            /// `user passwd` by the administrator: unlinks a linked account, else sets the password.
            Password(usize, usize),
            /// (tenant, name, active)
            Active(usize, usize, bool),
        }

        fn op() -> impl Strategy<Value = Op> {
            prop_oneof![
                3 => (0usize..2, 0usize..3, any::<bool>()).prop_map(|(t, u, o)| Op::Add(t, u, o)),
                3 => (0usize..2, 0usize..3, 0usize..3).prop_map(|(t, u, s)| Op::Link(t, u, s)),
                2 => (0usize..2, 0usize..3).prop_map(|(t, u)| Op::Password(t, u)),
                1 => (0usize..2, 0usize..3, any::<bool>()).prop_map(|(t, u, a)| Op::Active(t, u, a)),
            ]
        }

        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("app.db")).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let tenants: Vec<TenantCtx> = ["alpha", "beta"].iter().map(|n| reg.by_name(n).unwrap()).collect();
        let names = ["alice", "bob", "carol"];
        let subs = ["s1", "s2", "s3"];
        let iss = "https://auth.example";

        /// (account, identity, has a password) of every account of a tenant, disabled ones included.
        fn rows(db: &Db, t: &TenantCtx) -> Vec<(String, Option<String>, bool)> {
            let c = db.conn().unwrap();
            let mut st = c
                .prepare(
                    "SELECT user_id, oidc_subject, password_hash IS NOT NULL FROM user WHERE tenant_id = ?1 ORDER BY user_id",
                )
                .unwrap();
            st.query_map(params![t.name()], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? != 0))
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
        }

        let cases = std::env::var("PROPTEST_CASES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(32);
        let mut runner = TestRunner::new(PropConfig::with_cases(cases));
        let result = runner.run(&proptest::collection::vec(op(), 1..24), |ops| {
            for o in &ops {
                // The digest itself is not what this model checks: any non-NULL value is a password.
                let h = "hash";
                match *o {
                    Op::Add(t, u, oidc) => {
                        let set = if oidc {
                            db.user_add_oidc(&tenants[t], names[u], false)
                        } else {
                            db.user_add(&tenants[t], names[u], h, false)
                        };
                        let _ = set;
                    }
                    Op::Link(t, u, s) => {
                        let _ = db.user_oidc_link(&tenants[t], names[u], iss, subs[s]);
                    }
                    Op::Password(t, u) => {
                        let p = db.user_oidc_unlink_with_password(&tenants[t], names[u], h);
                        if !matches!(p, Ok(true)) {
                            let _ = db.user_set_password_hash(&tenants[t], names[u], h, true);
                        }
                    }
                    Op::Active(t, u, on) => {
                        let _ = db.user_set_active(&tenants[t], names[u], on);
                    }
                }
                // Invariants, after every step. A disabled account keeps its identity: linked by hand, it is a
                // state, not a password.
                for t in &tenants {
                    let rows = rows(&db, t);
                    for (u, sub, has_password) in &rows {
                        prop_assert!(!(sub.is_some() && *has_password), "{u} has a password and an identity");
                    }
                    let mut seen: Vec<(&str, &str)> = Vec::new();
                    for (u, sub, _) in &rows {
                        if let Some(s) = sub {
                            prop_assert!(!seen.contains(&(iss, s.as_str())), "{s} linked twice ({u})");
                            seen.push((iss, s.as_str()));
                        }
                    }
                    // And what the lookup answers is one of those accounts.
                    for s in subs {
                        if let Some(u) = db.user_by_oidc(t, iss, s).unwrap() {
                            prop_assert!(rows.iter().any(|(n, sub, _)| *n == u && sub.as_deref() == Some(s)));
                        }
                    }
                }
            }
            Ok(())
        });
        if let Err(e) = result {
            panic!("{e}");
        }
    }

    /// The session carries the account's state: set by the administrator → must change; chosen → not. Another
    /// account of the tenant and the same name in the other tenant are independent.
    #[test]
    fn session_carries_must_change() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("app.db")).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let (a, b) = (reg.by_name("alpha").unwrap(), reg.by_name("beta").unwrap());
        for (t, u) in [(&a, "alice"), (&a, "bob"), (&b, "alice")] {
            db.user_add(t, u, "h", false).unwrap();
        }
        let mac = |i: u8| [i; 32];
        db.session_add(&a, "alice", &mac(1), 60).unwrap();
        db.session_add(&a, "bob", &mac(2), 60).unwrap();
        db.session_add(&b, "alice", &mac(3), 60).unwrap();
        assert_eq!(
            db.session_user(&a, &mac(1)).unwrap().map(|r| (r.user, r.must_change)),
            Some(("alice".into(), true))
        );
        assert!(db.user_set_password_hash(&a, "alice", "h2", false).unwrap());
        assert_eq!(
            db.session_user(&a, &mac(1)).unwrap().map(|r| (r.user, r.must_change)),
            None
        ); // the change ended it
        db.session_add(&a, "alice", &mac(4), 60).unwrap();
        assert_eq!(
            db.session_user(&a, &mac(4)).unwrap().map(|r| (r.user, r.must_change)),
            Some(("alice".into(), false))
        );
        assert_eq!(
            db.session_user(&a, &mac(2)).unwrap().map(|r| (r.user, r.must_change)),
            Some(("bob".into(), true))
        ); // other user untouched
        assert_eq!(
            db.session_user(&b, &mac(3)).unwrap().map(|r| (r.user, r.must_change)),
            Some(("alice".into(), true))
        ); // other tenant untouched
        assert_eq!(
            db.session_user(&b, &mac(4)).unwrap().map(|r| (r.user, r.must_change)),
            None
        );
        assert!(!db.user_set_password_hash(&a, "carol", "h", false).unwrap());
        assert_eq!(db.user_must_change(&a, "carol").unwrap(), None);
    }

    /// The account list tells both states, each way.
    #[test]
    fn user_list_states() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("app.db")).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let a = reg.by_name("alpha").unwrap();
        db.user_add(&a, "alice", "h", false).unwrap();
        db.user_add(&a, "bob", "h", false).unwrap();
        assert!(db.totp_enable(&a, "bob", b"sealed", 1, &[]).unwrap());
        assert!(db.user_set_active(&a, "bob", false).unwrap());
        let l: Vec<_> = db
            .user_list(&a, 10)
            .unwrap()
            .into_iter()
            .map(|u| (u.user_id, u.active, u.totp))
            .collect();
        assert_eq!(l, [("alice".to_owned(), true, false), ("bob".to_owned(), false, true)]);
    }

    /// Anti-replay in SQL, for two requests that both passed the check in memory with the same code: only the first
    /// moves the step forward; an older step never; another account and the other tenant are independent; an account
    /// without two-step verification never.
    #[test]
    fn totp_step_is_used_once_in_sql() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("app.db")).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let (a, b) = (reg.by_name("alpha").unwrap(), reg.by_name("beta").unwrap());
        for (t, u) in [(&a, "alice"), (&a, "bob"), (&b, "alice")] {
            db.user_add(t, u, "h", false).unwrap();
            assert!(db.totp_enable(t, u, b"sealed", 10, &[]).unwrap());
        }
        assert!(!db.totp_use(&a, "alice", 10).unwrap()); // at the last step
        assert!(!db.totp_use(&a, "alice", 9).unwrap()); // below
        assert!(db.totp_use(&a, "alice", 11).unwrap()); // above
        assert!(!db.totp_use(&a, "alice", 11).unwrap()); // the second request with the same code
        assert!(db.totp_use(&a, "bob", 11).unwrap());
        assert!(db.totp_use(&b, "alice", 11).unwrap());
        db.totp_disable(&a, "alice").unwrap();
        assert!(!db.totp_use(&a, "alice", 50).unwrap()); // off
        assert!(!db.totp_use(&a, "carol", 50).unwrap()); // unknown
    }

    #[test]
    fn tenants_are_isolated_in_db() {
        let (reg, _a, _b) = two_tenants();
        let d = tempfile::tempdir().unwrap();
        let db = Db::open(&d.path().join("app.db")).unwrap();
        db.sync_tenants(reg.all()).unwrap();
        let (a, b) = (reg.by_name("alpha").unwrap(), reg.by_name("beta").unwrap());
        db.user_add(&a, "alice", "h", true).unwrap();
        db.user_add(&b, "alice", "h", false).unwrap(); // same name, distinct account
        assert!(db.user_add(&a, "alice", "h", false).is_err());
        assert_eq!(db.user_list(&a, 10).unwrap().len(), 1);
        assert_eq!(db.user_list(&b, 10).unwrap()[0].role, "user");
        // Composite foreign key: a token of A cannot target a user missing from A.
        let r = db.conn().unwrap().execute(
            "INSERT INTO app_token (tenant_id, token_id, user_id, mac, label, created_at) VALUES ('alpha','t','bob',x'00','',0)",
            [],
        );
        assert!(r.is_err());
        // Reopening: no new migration, data intact.
        drop(db);
        let db = Db::open(&d.path().join("app.db")).unwrap();
        assert_eq!(db.user_list(&a, 10).unwrap().len(), 1);
    }
}
