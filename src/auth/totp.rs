//! Two-step verification (TOTP, RFC 6238: HMAC-SHA-1, 30 s, 6 digits) and recovery codes.
//!
//! The secret is stored sealed with the tenant key (a database copy alone does not give it away); recovery codes are
//! stored as tenant HMAC digests only. A code is accepted once: its time step must be newer than the last one used.

use crate::tenant::TenantCtx;
use crate::{Error, Result};

/// Secret length (160 bits, RFC 4226 recommendation).
pub const SECRET_LEN: usize = 20;
/// Time step (seconds).
const PERIOD: u64 = 30;
/// Steps accepted on each side of the current one (clock drift of the phone).
const DRIFT: u64 = 1;
/// Recovery codes given at once.
pub const RECOVERY_CODES: usize = 10;
/// Alphabet of the recovery codes (Crockford's base 32, lowercase): no i, l, o, u, so 0 and 1 are unambiguous.
const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// HOTP value (RFC 4226) of `secret` at counter `step`, 6 digits.
pub fn hotp(secret: &[u8], step: u64) -> u32 {
    use hmac::{KeyInit, Mac};
    let Ok(mut m) = hmac::Hmac::<sha1::Sha1>::new_from_slice(secret) else {
        return u32::MAX; // unreachable: HMAC accepts any key length; never a 6-digit value
    };
    m.update(&step.to_be_bytes());
    let h: [u8; 20] = m.finalize().into_bytes().into();
    let off = usize::from(h.last().copied().unwrap_or(0) & 0x0f); // ≤ 15: four bytes always fit in 20
    let mut b = [0u8; 4];
    b.copy_from_slice(h.get(off..off + 4).unwrap_or(&[0xff; 4]));
    (u32::from_be_bytes(b) & 0x7fff_ffff) % 1_000_000
}

/// Time step of a Unix time.
pub fn step(unix: u64) -> u64 {
    unix / PERIOD
}

/// Current Unix time (seconds).
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The step that `code` matches around `now_step` (± `DRIFT`), newer than `last` (each code works once). The newest
/// match wins.
pub fn check(secret: &[u8], code: u32, now_step: u64, last: u64) -> Option<u64> {
    (now_step.saturating_sub(DRIFT)..=now_step.saturating_add(DRIFT))
        .rev()
        .find(|&s| s > last && hotp(secret, s) == code)
}

/// A 6-digit code typed by the user: digits, spaces allowed ("123 456"); anything else → `None`.
pub fn parse_code(input: &str) -> Option<u32> {
    let digits: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.len() != 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// A recovery code typed by the user, normalized: case, spaces and dashes ignored; 8 characters of `ALPHABET`.
pub fn parse_recovery(input: &str) -> Option<String> {
    let s: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_lowercase)
        .collect();
    (s.len() == 8 && s.bytes().all(|b| ALPHABET.contains(&b))).then_some(s)
}

/// `RECOVERY_CODES` new codes, `xxxx-xxxx` (40 bits each).
pub fn new_recovery_codes() -> Result<Vec<String>> {
    let mut raw = [0u8; RECOVERY_CODES * 8];
    getrandom::fill(&mut raw).map_err(|e| Error::Invalid(e.to_string()))?;
    Ok(raw
        .chunks(8)
        .map(|c| {
            let s: String = c
                .iter()
                .filter_map(|b| ALPHABET.get(usize::from(b & 31)).copied().map(char::from))
                .collect();
            format!("{}-{}", s.get(..4).unwrap_or_default(), s.get(4..).unwrap_or_default())
        })
        .collect())
}

/// Digest stored for a recovery code (normalized by `parse_recovery`), bound to the tenant and the user.
pub fn recovery_mac(t: &TenantCtx, user: &str, normalized: &str) -> [u8; 32] {
    t.mac(format!("recovery\0{user}\0{normalized}").as_bytes())
}

/// The secret offered while setting up, derived from the web session: nothing to store before it is confirmed, the
/// same QR code if the page is shown again, a new one in another session.
pub fn setup_secret(t: &TenantCtx, session_secret: &str) -> [u8; SECRET_LEN] {
    let m = t.mac(format!("totp-setup\0{session_secret}").as_bytes());
    let mut s = [0u8; SECRET_LEN];
    s.copy_from_slice(m.get(..SECRET_LEN).unwrap_or(&[0; SECRET_LEN]));
    s
}

/// Pad for sealing: HMAC of the tenant key over the user and a random nonce (a stream cipher built on a PRF).
fn pad(t: &TenantCtx, user: &str, nonce: &[u8]) -> [u8; 32] {
    let mut data = format!("totp-seal\0{user}\0").into_bytes();
    data.extend_from_slice(nonce);
    t.mac(&data)
}

/// Sealed secret as stored: 16-byte nonce, then the secret masked by `pad`.
pub fn seal(t: &TenantCtx, user: &str, secret: &[u8; SECRET_LEN]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|e| Error::Invalid(e.to_string()))?;
    let p = pad(t, user, &nonce);
    let mut out = nonce.to_vec();
    out.extend(secret.iter().zip(p).map(|(a, b)| a ^ b));
    Ok(out)
}

/// Opens a sealed secret; `None` if malformed.
pub fn unseal(t: &TenantCtx, user: &str, sealed: &[u8]) -> Option<[u8; SECRET_LEN]> {
    if sealed.len() != 16 + SECRET_LEN {
        return None;
    }
    let (nonce, ct) = sealed.split_at(16);
    let p = pad(t, user, nonce);
    let mut s = [0u8; SECRET_LEN];
    for ((o, a), b) in s.iter_mut().zip(ct).zip(p) {
        *o = a ^ b;
    }
    Some(s)
}

/// Base32 (RFC 4648, no padding): the key shown and put in the QR code.
pub fn base32(data: &[u8]) -> String {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.extend(
                A.get(usize::try_from((buf >> bits) & 31).unwrap_or(0))
                    .copied()
                    .map(char::from),
            );
        }
    }
    if bits > 0 {
        out.extend(
            A.get(usize::try_from((buf << (5 - bits)) & 31).unwrap_or(0))
                .copied()
                .map(char::from),
        );
    }
    out
}

/// The key grouped by 4 for typing by hand.
pub fn grouped(key: &str) -> String {
    key.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

/// `otpauth://` URI read by the authenticator apps. `issuer`: the host name the user signs in to.
pub fn uri(issuer: &str, user: &str, secret: &[u8]) -> String {
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode as enc};
    let (i, u) = (enc(issuer, NON_ALPHANUMERIC), enc(user, NON_ALPHANUMERIC));
    format!(
        "otpauth://totp/{i}:{u}?secret={}&issuer={i}&algorithm=SHA1&digits=6&period=30",
        base32(secret)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenant::tests::two_tenants;

    /// RFC 6238 appendix B (SHA-1 secret "12345678901234567890"), last 6 digits of the 8 given there.
    #[test]
    fn rfc6238_vectors() {
        let s = b"12345678901234567890";
        for (t, code) in [
            (59u64, 287_082u32),
            (1_111_111_109, 81_804),
            (1_111_111_111, 50_471),
            (1_234_567_890, 5_924),
            (2_000_000_000, 279_037),
            (20_000_000_000, 353_130),
        ] {
            assert_eq!(hotp(s, step(t)), code, "{t}");
        }
        // RFC 4226 appendix D (HOTP, same secret), counters 0 and 9.
        assert_eq!(hotp(s, 0), 755_224);
        assert_eq!(hotp(s, 9), 520_489);
    }

    /// Window: the previous, current and next steps; never two steps away; never a step already used or older.
    #[test]
    fn check_window_and_replay() {
        let s = b"12345678901234567890";
        let now = 1000;
        for (st, ok) in [(998, false), (999, true), (1000, true), (1001, true), (1002, false)] {
            assert_eq!(check(s, hotp(s, st), now, 0) == Some(st), ok, "{st}");
        }
        assert_eq!(check(s, hotp(s, 1000), now, 1000), None); // used
        assert_eq!(check(s, hotp(s, 999), now, 1000), None); // older than the last used
        assert_eq!(check(s, hotp(s, 1001), now, 1000), Some(1001));
        assert_eq!(check(s, hotp(s, 0), 0, 0), None); // step 0 can never be newer than "nothing used"
        assert_eq!(check(s, hotp(s, 1), 0, 0), Some(1)); // no underflow at the epoch
    }

    #[test]
    fn code_and_recovery_parsing() {
        assert_eq!(parse_code("123456"), Some(123_456));
        assert_eq!(parse_code(" 012 345 "), Some(12_345));
        for bad in ["12345", "1234567", "12345a", "", "١٢٣٤٥٦", "+12345", "12 34 5"] {
            assert_eq!(parse_code(bad), None, "{bad}");
        }
        assert_eq!(parse_recovery("K4P2-9XQ7").as_deref(), Some("k4p29xq7"));
        assert_eq!(parse_recovery(" k4p2 9xq7 ").as_deref(), Some("k4p29xq7"));
        for bad in [
            "k4p2-9xq",
            "k4p2-9xq77",
            "k4p2-9xqu",
            "k4p2-9xqi",
            "k4p2-9xqo",
            "k4p2_9xq7",
            "",
            "ｋ4p2-9xq7",
        ] {
            assert_eq!(parse_recovery(bad), None, "{bad}");
        }
    }

    #[test]
    fn recovery_codes_are_well_formed_and_distinct() {
        let a = new_recovery_codes().unwrap();
        assert_eq!(a.len(), RECOVERY_CODES);
        for c in &a {
            assert_eq!(c.len(), 9, "{c}");
            assert!(parse_recovery(c).is_some(), "{c}");
        }
        let mut d = a.clone();
        d.sort();
        d.dedup();
        assert_eq!(d.len(), RECOVERY_CODES);
        assert_ne!(a, new_recovery_codes().unwrap());
    }

    /// Sealing: round trip; another user, another tenant or a changed byte never open the same secret; two seals of the
    /// same secret differ (random nonce).
    #[test]
    fn seal_is_bound_to_tenant_and_user() {
        let (reg, _a, _b) = two_tenants();
        let (a, b) = (reg.by_name("alpha").unwrap(), reg.by_name("beta").unwrap());
        let s = [9u8; SECRET_LEN];
        let x = seal(&a, "alice", &s).unwrap();
        assert_eq!(unseal(&a, "alice", &x), Some(s));
        assert_ne!(unseal(&a, "bob", &x), Some(s));
        assert_ne!(unseal(&b, "alice", &x), Some(s));
        assert_ne!(seal(&a, "alice", &s).unwrap(), x);
        assert!(!x.windows(SECRET_LEN).any(|w| w == s)); // never stored in clear
        let mut y = x.clone();
        y[20] ^= 1;
        assert_ne!(unseal(&a, "alice", &y), Some(s));
        assert_eq!(unseal(&a, "alice", &x[1..]), None);
        assert_eq!(unseal(&a, "alice", &[]), None);
        // Setup secret: per session and per tenant.
        assert_eq!(setup_secret(&a, "s1"), setup_secret(&a, "s1"));
        assert_ne!(setup_secret(&a, "s1"), setup_secret(&a, "s2"));
        assert_ne!(setup_secret(&a, "s1"), setup_secret(&b, "s1"));
    }

    #[test]
    fn base32_and_uri() {
        // RFC 4648 section 10.
        for (i, o) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32(i.as_bytes()), o);
        }
        assert_eq!(base32(&[0xff; 20]).len(), 32);
        assert_eq!(grouped("ABCDEFGHIJ"), "ABCD EFGH IJ");
        let u = uri("files.alpha.example:8443", "alice", b"foobar");
        assert_eq!(
            u,
            "otpauth://totp/files%2Ealpha%2Eexample%3A8443:alice?secret=MZXW6YTBOI&issuer=files%2Ealpha%2Eexample%3A8443&algorithm=SHA1&digits=6&period=30"
        );
    }

    proptest::proptest! {
        /// Any code is accepted at most once (anti-replay), only inside the window, and parse_code reads back what it
        /// is given.
        #[test]
        fn a_code_is_accepted_once(secret in proptest::array::uniform20(proptest::prelude::any::<u8>()), now in 2u64..u64::MAX / 2, off in 0u64..5) {
            let target = now - 2 + off; // steps now-2 ..= now+2
            let code = hotp(&secret, target);
            proptest::prop_assert!(code < 1_000_000);
            proptest::prop_assert_eq!(parse_code(&format!("{code:06}")), Some(code));
            if let Some(st) = check(&secret, code, now, 0) {
                proptest::prop_assert!(st.abs_diff(now) <= DRIFT);
                proptest::prop_assert_eq!(hotp(&secret, st), code);
                proptest::prop_assert!(check(&secret, code, now, st).is_none_or(|s2| s2 > st));
            }
            if target.abs_diff(now) <= DRIFT {
                proptest::prop_assert!(check(&secret, code, now, 0).is_some());
            }
        }
    }
}
