//! OIDC client: the `https` URL grammar of the configuration and the back channel, and the protocol core — flow values,
//! authorization URL, discovery document, `id_token` checks. No I/O here: the network calls go through a Casper channel
//! (`src/fs/casper.rs`) in `oidc_net.rs`, and `UserCtx` is built in `auth/` from a `Verified` value only.
//! Design: `docs/dev/oidc-proposal.md`; plan: `docs/dev/oidc-implementation-plan.md`.

use crate::tenant::TenantCtx;
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::Deserialize;

/// Longest accepted URL: bounded before parsing, like every provider response.
const MAX_URL: usize = 2_048;
/// Longest accepted flow cookie: `until.random.next.mac`, all of it keyed.
const MAX_COOKIE: usize = 256;
/// Lifetime of a flow, seconds (the cookie carries its end). Also the flow cookie's `Max-Age`.
pub const FLOW_TTL: i64 = 600;
/// Longest accepted discovery document and token response.
const MAX_PROVIDER_JSON: usize = 256 * 1024;
/// Same bound, public: the back channel (`oidc_net`) refuses a larger body before parsing.
pub const MAX_PROVIDER_JSON_BYTES: usize = MAX_PROVIDER_JSON;
/// Longest accepted `id_token`.
const MAX_ID_TOKEN: usize = 64 * 1024;
/// Clock skew tolerated on `exp` and `iat`, seconds.
const SKEW: i64 = 60;

/// Why an `https` URL was refused. Logged and asserted by the tests, never shown to a browser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlError {
    TooLong,
    NotHttps,
    NotPrintableAscii,
    UserInfo,
    Fragment,
    Backslash,
    EmptyHost,
    BadHost,
    BadPort,
}

impl std::fmt::Display for UrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooLong => "longer than 2048 bytes",
            Self::NotHttps => "must start with https://",
            Self::NotPrintableAscii => "printable ASCII only",
            Self::UserInfo => "no user info",
            Self::Fragment => "no fragment",
            Self::Backslash => "no backslash",
            Self::EmptyHost => "empty host",
            Self::BadHost => "host: lowercase letters, digits, '.' and '-' only",
            Self::BadPort => "port: a number from 1 to 65535",
        })
    }
}

/// An `https` URL kept **byte for byte**: the issuer is compared exactly with the `iss` of the `id_token`, so a
/// trailing slash or a path is never normalized away.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpsUrl {
    /// The accepted bytes, exactly as given.
    pub raw: String,
    /// Lowercase host name. No IPv6 literal: a fixed address goes in `connect_addr`.
    pub host: String,
    /// 443 when the URL gives no port.
    pub port: u16,
    /// Everything after the authority: `""`, `"/path"`, `"/path?query"`.
    pub path_and_query: String,
}

impl HttpsUrl {
    pub fn parse(raw: &str) -> Result<Self, UrlError> {
        if raw.len() > MAX_URL {
            return Err(UrlError::TooLong);
        }
        if !raw.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
            return Err(UrlError::NotPrintableAscii);
        }
        let rest = raw.strip_prefix("https://").ok_or(UrlError::NotHttps)?;
        if rest.contains('#') {
            return Err(UrlError::Fragment);
        }
        if rest.contains('\\') {
            return Err(UrlError::Backslash);
        }
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, path_and_query) = rest.split_at(end);
        if authority.contains('@') {
            return Err(UrlError::UserInfo);
        }
        let (host, port) = parse_host_port(authority)?;
        Ok(Self {
            raw: raw.to_string(),
            host,
            port,
            path_and_query: path_and_query.to_string(),
        })
    }
}

/// `host` or `host:port` (443 when absent): the authority of an `https` URL, and the grammar of
/// `backchannel_hosts`.
pub fn parse_host_port(s: &str) -> Result<(String, u16), UrlError> {
    let (host, port) = match s.split_once(':') {
        // Digits only: `"+80".parse::<u16>()` would accept a leading `+` (port 80, cleartext-looking).
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            (h, p.parse::<u16>().map_err(|_| UrlError::BadPort)?)
        }
        Some(_) => return Err(UrlError::BadPort),
        None => (s, 443),
    };
    if host.is_empty() {
        return Err(UrlError::EmptyHost);
    }
    let allowed = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-';
    let named = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !host.bytes().all(allowed) || !host.bytes().any(named) {
        return Err(UrlError::BadHost);
    }
    if port == 0 {
        return Err(UrlError::BadPort);
    }
    Ok((host.to_string(), port))
}

/// Why a provider response, a flow value or an `id_token` was refused. Small on purpose: it names the check that
/// failed, for the log and the tests, and never reaches the browser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    TooLarge,
    NotJson,
    Issuer,
    Endpoint,
    GrantType,
    Pkce,
    ClientAuth,
    Cookie,
    State,
    TokenResponse,
    IdToken,
    Audience,
    Expired,
    Nonce,
    Subject,
    Next,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "response too large",
            Self::NotJson => "malformed JSON",
            Self::Issuer => "issuer mismatch",
            Self::Endpoint => "missing or undeclared endpoint",
            Self::GrantType => "authorization code not offered",
            Self::Pkce => "S256 not offered",
            Self::ClientAuth => "no client authentication method",
            Self::Cookie => "flow cookie refused",
            Self::State => "state mismatch",
            Self::TokenResponse => "token response refused",
            Self::IdToken => "id_token malformed",
            Self::Audience => "aud/azp mismatch",
            Self::Expired => "expired or from the future",
            Self::Nonce => "nonce mismatch",
            Self::Subject => "subject invalid",
            Self::Next => "target not allowed",
        })
    }
}

/// What the protocol needs from the configuration: the issuer (byte for byte), the client id, and the only hosts the
/// token endpoint may live on. No secret here: `oidc_net` reads it for the exchange only.
#[derive(Clone, Debug)]
pub struct OidcClient {
    pub issuer: HttpsUrl,
    pub client_id: String,
    /// Declared `backchannel_hosts` (`host`, port 443 when absent).
    backchannel: Vec<(String, u16)>,
}

impl OidcClient {
    pub fn new(issuer: &str, client_id: &str, backchannel: &[String]) -> Result<Self, UrlError> {
        let issuer = HttpsUrl::parse(issuer)?;
        let mut hosts = Vec::with_capacity(backchannel.len());
        for h in backchannel {
            hosts.push(parse_host_port(h)?);
        }
        Ok(Self {
            issuer,
            client_id: client_id.to_string(),
            backchannel: hosts,
        })
    }

    /// The declared back channel hosts (`host`, port 443 when absent): the Casper allowlist (ADR-6) and the tests.
    pub fn backchannel_hosts(&self) -> &[(String, u16)] {
        &self.backchannel
    }

    /// The token endpoint may live on the issuer's host and port, or on a declared back channel host. Nothing else:
    /// the client secret and the code only go there.
    fn endpoint_allowed(&self, u: &HttpsUrl) -> bool {
        (u.host == self.issuer.host && u.port == self.issuer.port)
            || self.backchannel.iter().any(|(h, p)| h == &u.host && *p == u.port)
    }
}

/// Values of one authorization flow. The cookie holds everything (`until.random.next.mac`), so the server keeps no
/// state: `state`, `nonce` and the PKCE verifier are derived from it with the tenant key, and never left the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flow {
    /// The exact cookie value: every derived value is keyed by it.
    pub cookie: String,
    /// Echoed by the provider, compared in constant time.
    pub state: String,
    /// Bound into the `id_token` the provider returns.
    pub nonce: String,
    /// PKCE verifier; the challenge is what the browser sees.
    pub verifier: String,
    /// Where the browser goes afterwards: one of `after_login`'s targets, or `""` (the files page).
    pub next: String,
    /// End of the flow (Unix time): its cookie is refused after it, and remembered as used until it.
    pub until: i64,
}

impl Flow {
    /// PKCE challenge: base64url without padding of SHA-256(verifier).
    pub fn challenge(&self) -> String {
        use sha2::Digest;
        Base64UrlUnpadded::encode_string(&sha2::Sha256::digest(self.verifier.as_bytes()))
    }
}

/// A new flow for `next` (an `after_login` target, or `""` = the default, the files page), valid until
/// `now + 600`. The cookie is built and read back through the same checks, so nothing can be issued that
/// `read_flow` would refuse.
pub fn new_flow(t: &TenantCtx, next: &str, now: i64) -> Result<Flow, Refusal> {
    let next = if next.is_empty() {
        String::new()
    } else {
        after_login(next).ok_or(Refusal::Next)?
    };
    let random = crate::auth::random_hex::<32>().map_err(|_| Refusal::Cookie)?;
    let payload = format!("{}.{random}.{next}", now.saturating_add(FLOW_TTL));
    let cookie = format!("{payload}.{}", keyed(t, "oidc-cookie", &payload));
    read_flow(t, &cookie, now).ok_or(Refusal::Cookie)
}

/// The flow a cookie proves, if this tenant issued it and it has not expired. `None`: anything else (a byte changed, the
/// other tenant's key, an expired or over-long value), never a partial answer.
pub fn read_flow(t: &TenantCtx, cookie: &str, now: i64) -> Option<Flow> {
    if cookie.is_empty() || cookie.len() > MAX_COOKIE {
        return None;
    }
    let (payload, mac) = cookie.rsplit_once('.')?;
    if !crate::auth::constant_time_eq(keyed(t, "oidc-cookie", payload).as_bytes(), mac.as_bytes()) {
        return None;
    }
    let (until, rest) = payload.split_once('.')?;
    let (random, next) = rest.split_once('.')?;
    let until: i64 = until.parse().ok()?;
    // Not expired, and not issued with a longer life than `FLOW_TTL` (a stretched `until` is refused).
    if until <= now || until > now.saturating_add(FLOW_TTL) || random.len() != 64 || !is_hex(random) {
        return None;
    }
    if !(next.is_empty() || after_login(next)? == next) {
        return None;
    }
    Some(Flow {
        until,
        state: keyed(t, "oidc-state", cookie),
        nonce: keyed(t, "oidc-nonce", cookie),
        verifier: keyed(t, "oidc-pkce", cookie),
        cookie: cookie.to_string(),
        next: next.to_string(),
    })
}

/// Flows already used by a callback, by their `state` (unique per flow), until their end: the cookie is stateless, so
/// without this a flow could be replayed for its 10 minutes (one back-channel call each). Bounded (§0.4).
#[derive(Debug, Default)]
pub struct UsedFlows(std::sync::Mutex<std::collections::HashMap<String, i64>>);

/// Live flows remembered per tenant; full of live ones, a new callback is refused (fail closed).
const MAX_USED_FLOWS: usize = 4096;

impl UsedFlows {
    /// Is this the flow's first callback? Records it. Poisoned lock or table full of live flows: no.
    pub fn first_use(&self, flow: &Flow, now: i64) -> bool {
        let Ok(mut m) = self.0.lock() else { return false };
        if m.contains_key(&flow.state) {
            return false;
        }
        if m.len() >= MAX_USED_FLOWS {
            m.retain(|_, until| *until > now);
            if m.len() >= MAX_USED_FLOWS {
                tracing::warn!("used single sign-on flow table full");
                return false;
            }
        }
        m.insert(flow.state.clone(), flow.until);
        true
    }
}

/// Does the provider echo this flow's `state`? Constant time: a timing oracle on `state` would be a login CSRF oracle.
pub fn state_ok(flow: &Flow, received: &str) -> bool {
    crate::auth::constant_time_eq(flow.state.as_bytes(), received.as_bytes())
}

/// Where a sign-in may send the browser: the file of a link (`/index.php/f/<digits>`), the account page, the Login
/// Flow confirmation with its exact token syntax. Nothing else: an open redirect is a login CSRF.
pub fn after_login(raw: &str) -> Option<String> {
    let file = raw
        .strip_prefix("/index.php/f/")
        .is_some_and(|id| (1..=20).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_digit()));
    let flow = raw
        .strip_prefix("/index.php/login/v2/flow/")
        .is_some_and(|t| t.len() == 64 && is_hex(t));
    (file || flow || raw == "/web/account").then(|| raw.to_string())
}

/// The authorization request, with every parameter of the code flow and PKCE S256. No secret and no verifier inside.
pub fn authorize_url(d: &Discovery, c: &OidcClient, base: &str, f: &Flow) -> String {
    let redirect = format!("{base}/login/oidc/callback");
    let challenge = f.challenge();
    let mut url = d.authorization_endpoint.raw.clone();
    url.push(if d.authorization_endpoint.path_and_query.contains('?') {
        '&'
    } else {
        '?'
    });
    for (i, (k, v)) in [
        ("response_type", "code"),
        ("response_mode", "query"),
        ("scope", "openid"),
        ("client_id", c.client_id.as_str()),
        ("redirect_uri", redirect.as_str()),
        ("state", f.state.as_str()),
        ("nonce", f.nonce.as_str()),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ]
    .iter()
    .enumerate()
    {
        if i > 0 {
            url.push('&');
        }
        url.push_str(&encode(k));
        url.push('=');
        url.push_str(&encode(v));
    }
    url
}

/// Client authentication the provider accepts: RFC 6749 §2.3.1 form encoding in a Basic header, or the same fields in
/// the body. `Basic` unless only `client_secret_post` is offered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientAuth {
    Basic,
    Post,
}

/// The provider's published configuration, checked before use. Every endpoint is `https` and the token endpoint is a
/// destination this tenant declared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discovery {
    pub authorization_endpoint: HttpsUrl,
    pub token_endpoint: HttpsUrl,
    /// The authorization endpoint echoes `iss` (RFC 9207): the callback may then require it.
    pub iss_parameter: bool,
    pub auth: ClientAuth,
}

#[derive(Deserialize)]
struct RawDiscovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    response_types_supported: Vec<String>,
    #[serde(default)]
    code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(default)]
    authorization_response_iss_parameter_supported: bool,
}

/// Reads and checks the discovery document: size bound before parsing, `issuer` equal byte for byte, `https` endpoints,
/// token endpoint among the declared destinations, `code` offered, PKCE refused only when the methods are listed
/// without `S256`, and a client authentication method. Duplicate keys are refused by the derived struct.
pub fn parse_discovery(raw: &[u8], c: &OidcClient) -> Result<Discovery, Refusal> {
    if raw.len() > MAX_PROVIDER_JSON {
        return Err(Refusal::TooLarge);
    }
    let d: RawDiscovery = serde_json::from_slice(raw).map_err(|_| Refusal::NotJson)?;
    if d.issuer != c.issuer.raw {
        return Err(Refusal::Issuer);
    }
    let endpoint = |s: &str| HttpsUrl::parse(s).map_err(|_| Refusal::Endpoint);
    let authorization_endpoint = endpoint(&d.authorization_endpoint)?;
    let token_endpoint = endpoint(&d.token_endpoint)?;
    if !c.endpoint_allowed(&token_endpoint) {
        return Err(Refusal::Endpoint);
    }
    if !d.response_types_supported.iter().any(|r| r == "code") {
        return Err(Refusal::GrantType);
    }
    let methods = &d.code_challenge_methods_supported;
    if !methods.is_empty() && !methods.iter().any(|m| m == "S256") {
        return Err(Refusal::Pkce);
    }
    let auths = &d.token_endpoint_auth_methods_supported;
    let auth = if auths.is_empty() || auths.iter().any(|a| a == "client_secret_basic") {
        ClientAuth::Basic
    } else if auths.iter().any(|a| a == "client_secret_post") {
        ClientAuth::Post
    } else {
        return Err(Refusal::ClientAuth);
    };
    Ok(Discovery {
        authorization_endpoint,
        token_endpoint,
        iss_parameter: d.authorization_response_iss_parameter_supported,
        auth,
    })
}

#[derive(Deserialize)]
struct RawToken {
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// The `id_token` of a token response. A provider error, a missing or over-long token, a non-string or duplicate field:
/// refused. Nothing else of the response is read (no access or refresh token is used).
pub fn parse_token_response(raw: &[u8]) -> Result<String, Refusal> {
    if raw.len() > MAX_PROVIDER_JSON {
        return Err(Refusal::TooLarge);
    }
    let r: RawToken = serde_json::from_slice(raw).map_err(|_| Refusal::TokenResponse)?;
    if r.error.is_some() {
        return Err(Refusal::TokenResponse);
    }
    match r.id_token {
        Some(t) if !t.is_empty() && t.len() <= MAX_ID_TOKEN => Ok(t),
        _ => Err(Refusal::TokenResponse),
    }
}

#[derive(Deserialize)]
struct RawClaims {
    iss: String,
    /// A string, or an array of strings (several audiences then need `azp`).
    aud: Audience,
    #[serde(default)]
    azp: Option<String>,
    exp: f64,
    #[serde(default)]
    iat: Option<f64>,
    #[serde(default)]
    nonce: Option<String>,
    sub: String,
    #[serde(default)]
    amr: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

/// Proof that an `id_token` passed every check. Built here only: the web path finds an account through it, and
/// `UserCtx` comes from that account. Fields private, read through the accessors.
#[derive(Debug)]
pub struct Verified {
    issuer: String,
    subject: String,
    amr: Vec<String>,
}

impl Verified {
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
    pub fn subject(&self) -> &str {
        &self.subject
    }
    /// Authentication methods the provider reports (`amr`), empty when it says nothing.
    pub fn amr(&self) -> &[String] {
        &self.amr
    }
}

/// Checks the `id_token` the token endpoint returned over verified TLS (OIDC Core §3.1.3.7: the signature is not used,
/// and `alg` decides nothing). Size bound, three segments, payload only, `iss` equal, `aud`/`azp`, `exp` and `iat` with
/// 60 s of skew, `nonce` in constant time, `sub` in visible ASCII.
pub fn check_id_token(raw: &str, c: &OidcClient, f: &Flow, now: i64) -> Result<Verified, Refusal> {
    if raw.len() > MAX_ID_TOKEN {
        return Err(Refusal::TooLarge);
    }
    let mut segments = raw.split('.');
    let (Some(_header), Some(payload), Some(signature), None) =
        (segments.next(), segments.next(), segments.next(), segments.next())
    else {
        return Err(Refusal::IdToken);
    };
    if _header.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(Refusal::IdToken);
    }
    let bytes = Base64UrlUnpadded::decode_vec(payload).map_err(|_| Refusal::IdToken)?;
    let claims: RawClaims = serde_json::from_slice(&bytes).map_err(|_| Refusal::IdToken)?;
    if claims.iss != c.issuer.raw {
        return Err(Refusal::Issuer);
    }
    let audiences: Vec<&str> = match &claims.aud {
        Audience::One(a) => vec![a.as_str()],
        Audience::Many(v) => v.iter().map(String::as_str).collect(),
    };
    if !audiences.iter().any(|a| *a == c.client_id) {
        return Err(Refusal::Audience);
    }
    if claims.azp.as_deref().is_some_and(|azp| azp != c.client_id) {
        return Err(Refusal::Audience);
    }
    if audiences.len() > 1 && claims.azp.is_none() {
        return Err(Refusal::Audience);
    }
    // `exp` must be in the future (60 s of skew); `iat` close to now, not from the future nor long past.
    let exp = seconds(claims.exp).ok_or(Refusal::Expired)?;
    if exp <= now - SKEW {
        return Err(Refusal::Expired);
    }
    if let Some(iat) = claims.iat {
        let iat = seconds(iat).ok_or(Refusal::Expired)?;
        if iat > now + SKEW || iat < now - 600 {
            return Err(Refusal::Expired);
        }
    }
    match &claims.nonce {
        Some(n) if crate::auth::constant_time_eq(n.as_bytes(), f.nonce.as_bytes()) => {}
        _ => return Err(Refusal::Nonce),
    }
    if !valid_subject(&claims.sub) {
        return Err(Refusal::Subject);
    }
    let amr = claims.amr.unwrap_or_default();
    if amr
        .iter()
        .any(|a| a.is_empty() || a.len() > 32 || !a.bytes().all(|b| (0x21..=0x7e).contains(&b)))
    {
        return Err(Refusal::Subject);
    }
    Ok(Verified {
        issuer: claims.iss,
        subject: claims.sub,
        amr,
    })
}

/// Longest accepted `sub` (OIDC Core: 255 ASCII characters at most).
pub const SUBJECT_MAX: usize = 255;

/// What a provider identity may hold: 1 to 255 visible ASCII characters.
pub fn valid_subject(s: &str) -> bool {
    (1..=SUBJECT_MAX).contains(&s.len()) && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// `hex(t.mac("<name>\0" + input))`: a value only this tenant can produce, which is what makes a tampered cookie,
/// `state`, `nonce` or verifier useless.
fn keyed(t: &TenantCtx, name: &str, input: &str) -> String {
    crate::auth::hex(&t.mac(format!("{name}\0{input}").as_bytes()))
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A JSON number as whole seconds. Not finite (`1e999`) or outside `i64`: refused, never rounded into something valid.
fn seconds(v: f64) -> Option<i64> {
    if !v.is_finite() || v.abs() > 9e15 {
        return None;
    }
    Some(v as i64)
}

/// Percent-encoding of a query/form value: the unreserved characters are kept, everything else is escaped.
/// Used by `authorize_url` and, publicly, by the back channel (`oidc_net`) for the token form.
pub fn encode_query(v: &str) -> String {
    encode(v)
}

/// Percent-encoding of a query value: the unreserved characters are kept, everything else is escaped.
fn encode(v: &str) -> String {
    const UNRESERVED: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'~');
    percent_encoding::utf8_percent_encode(v, UNRESERVED).to_string()
}

/// Fuzzing (`fuzz/fuzz_targets/oidc_url.rs`): any string, no panic; an accepted URL reparses to itself and keeps its
/// shape (length bound, a port, a lowercase host made of the allowed characters).
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
#[allow(clippy::panic)]
pub fn fuzz_url(data: &[u8]) {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let Ok(u) = HttpsUrl::parse(s) else { return };
    assert!(u.raw == s && u.raw.len() <= MAX_URL && u.port != 0, "{s:?}");
    assert!(
        u.host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    );
    assert_eq!(HttpsUrl::parse(&u.raw), Ok(u), "{s:?}");
}

/// Fuzzing (`fuzz/fuzz_targets/oidc_provider.rs`): a provider response of any bytes — the discovery document
/// and the token response are refused or parsed, never a panic; an `id_token` of any shape likewise.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
#[allow(clippy::panic)]
pub fn fuzz_provider(data: &[u8]) {
    let Ok(c) = OidcClient::new("https://auth.example", "client", &["token.auth.example".into()]) else {
        return;
    };
    let _ = parse_discovery(data, &c);
    if let Ok(token) = parse_token_response(data) {
        let flow = Flow {
            cookie: "fuzz".into(),
            state: "s".into(),
            nonce: "n".into(),
            verifier: "v".into(),
            next: String::new(),
            until: 0,
        };
        let _ = check_id_token(&token, &c, &flow, 1_700_000_000);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenant::tests::two_tenants;

    fn refusal(s: &str) -> UrlError {
        match HttpsUrl::parse(s) {
            Ok(u) => panic!("accepted: {s:?} -> {u:?}"),
            Err(e) => e,
        }
    }

    #[test]
    fn accepted_urls_keep_their_bytes() {
        for (s, host, port, pq) in [
            ("https://auth.example", "auth.example", 443, ""),
            ("https://auth.example/", "auth.example", 443, "/"),
            ("https://auth.example:8443", "auth.example", 8443, ""),
            ("https://auth.example:1", "auth.example", 1, ""),
            ("https://auth.example:65535", "auth.example", 65535, ""),
            ("https://auth.example:443/path", "auth.example", 443, "/path"),
            // A provider with a path and a trailing slash (authentik): kept exactly.
            (
                "https://auth.example/application/o/alpha/",
                "auth.example",
                443,
                "/application/o/alpha/",
            ),
            ("https://auth.example/x?y=1&z=%20", "auth.example", 443, "/x?y=1&z=%20"),
            ("https://a.b-c.d.example/", "a.b-c.d.example", 443, "/"),
        ] {
            let u = HttpsUrl::parse(s).unwrap();
            assert_eq!(
                (u.raw.as_str(), u.host.as_str(), u.port, u.path_and_query.as_str()),
                (s, host, port, pq)
            );
        }
    }

    #[test]
    fn refusals() {
        // 2048 bytes: at the bound; 2049: too long.
        let mut at = String::from("https://auth.example/");
        at.push_str(&"a".repeat(MAX_URL - at.len()));
        assert_eq!(at.len(), MAX_URL);
        assert!(HttpsUrl::parse(&at).is_ok());
        assert_eq!(refusal(&format!("{at}a")), UrlError::TooLong);
        assert_eq!(refusal("http://auth.example"), UrlError::NotHttps);
        assert_eq!(refusal("HTTP://auth.example"), UrlError::NotHttps);
        assert_eq!(refusal("https:/auth.example"), UrlError::NotHttps);
        assert_eq!(refusal("auth.example"), UrlError::NotHttps); // the discovery URLs are absolute too
        assert_eq!(refusal(""), UrlError::NotHttps);
        assert_eq!(refusal("https://auth.exämple"), UrlError::NotPrintableAscii);
        assert_eq!(refusal("https://auth.example\u{7}"), UrlError::NotPrintableAscii);
        assert_eq!(refusal("https://auth.example\n"), UrlError::NotPrintableAscii);
        assert_eq!(refusal("https://auth.example "), UrlError::BadHost); // a space is not a host character
        assert_eq!(refusal("https://user@auth.example"), UrlError::UserInfo);
        assert_eq!(refusal("https://user:pw@auth.example"), UrlError::UserInfo);
        assert_eq!(refusal("https://auth.example/#top"), UrlError::Fragment);
        assert_eq!(refusal("https://auth.example\\path"), UrlError::Backslash);
        assert_eq!(refusal("https://"), UrlError::EmptyHost);
        assert_eq!(refusal("https:///path"), UrlError::EmptyHost);
        assert_eq!(refusal("https://AUTH.example"), UrlError::BadHost);
        assert_eq!(refusal("https://auth_example"), UrlError::BadHost);
        assert_eq!(refusal("https://..."), UrlError::BadHost);
        assert_eq!(refusal("https://auth.example:0"), UrlError::BadPort);
        assert_eq!(refusal("https://auth.example:65536"), UrlError::BadPort);
        assert_eq!(refusal("https://auth.example:99999"), UrlError::BadPort);
        assert_eq!(refusal("https://auth.example:"), UrlError::BadPort);
        assert_eq!(refusal("https://auth.example:-1"), UrlError::BadPort);
        assert_eq!(refusal("https://auth.example:1:2"), UrlError::BadPort);
        assert_eq!(refusal("https://auth.example:443x"), UrlError::BadPort);
        // A leading `+` would parse as a port (`"+80".parse::<u16>()` is Ok(80)): refused, digits only.
        assert_eq!(refusal("https://auth.example:+80"), UrlError::BadPort);
        assert_eq!(refusal("https://auth.example:+0"), UrlError::BadPort);
        assert_eq!(refusal("https://auth.example: 80"), UrlError::BadPort);
        assert_eq!(refusal("https://auth.example:80 "), UrlError::BadPort);
        assert_eq!(refusal("https://auth.example:0x50"), UrlError::BadPort);
    }

    /// The same grammar serves `backchannel_hosts` (`host` or `host:port`).
    #[test]
    fn host_port_grammar() {
        assert_eq!(
            parse_host_port("token.auth.example").unwrap(),
            ("token.auth.example".into(), 443)
        );
        assert_eq!(
            parse_host_port("auth.example:8443").unwrap(),
            ("auth.example".into(), 8443)
        );
        assert_eq!(parse_host_port("auth.example:0"), Err(UrlError::BadPort));
        assert_eq!(parse_host_port("auth.example:+443"), Err(UrlError::BadPort));
        assert_eq!(parse_host_port("auth.example:"), Err(UrlError::BadPort));
        assert_eq!(parse_host_port(""), Err(UrlError::EmptyHost));
        assert_eq!(parse_host_port("Auth.example"), Err(UrlError::BadHost));
        assert_eq!(parse_host_port("auth.example/path"), Err(UrlError::BadHost));
        assert_eq!(parse_host_port("auth.example?x"), Err(UrlError::BadHost));
        assert_eq!(parse_host_port("auth.example:+443"), Err(UrlError::BadPort));
    }

    /// Each refusal says what an administrator has to fix, and no two say the same thing.
    #[test]
    fn refusal_messages() {
        let all = [
            UrlError::TooLong,
            UrlError::NotHttps,
            UrlError::NotPrintableAscii,
            UrlError::UserInfo,
            UrlError::Fragment,
            UrlError::Backslash,
            UrlError::EmptyHost,
            UrlError::BadHost,
            UrlError::BadPort,
        ];
        let mut seen = std::collections::HashSet::new();
        for e in all {
            assert!(seen.insert(e.to_string()), "duplicate message: {e}");
        }
        let all = [
            Refusal::TooLarge,
            Refusal::NotJson,
            Refusal::Issuer,
            Refusal::Endpoint,
            Refusal::GrantType,
            Refusal::Pkce,
            Refusal::ClientAuth,
            Refusal::Cookie,
            Refusal::State,
            Refusal::TokenResponse,
            Refusal::IdToken,
            Refusal::Audience,
            Refusal::Expired,
            Refusal::Nonce,
            Refusal::Subject,
            Refusal::Next,
        ];
        let mut seen = std::collections::HashSet::new();
        for e in all {
            assert!(seen.insert(e.to_string()), "duplicate message: {e}");
        }
    }

    // ---- the protocol core: one valid fixture, one change per assertion ----

    const NOW: i64 = 1_760_000_000;
    const ISS: &str = "https://auth.example";

    fn client() -> OidcClient {
        OidcClient::new(ISS, "beastbox-alpha", &[]).unwrap()
    }

    fn flow(t: &TenantCtx) -> Flow {
        new_flow(t, "/web/account", NOW).unwrap()
    }

    /// A discovery document with `over` added (or a changed value) at the top level.
    fn discovery(extra: &str) -> String {
        format!(
            r#"{{"issuer":"{ISS}","authorization_endpoint":"https://auth.example/authorize",
                "token_endpoint":"https://auth.example/token",
                "response_types_supported":["code"],"code_challenge_methods_supported":["S256"],
                "token_endpoint_auth_methods_supported":["client_secret_basic"]{extra}}}"#
        )
    }

    fn base64url(b: &[u8]) -> String {
        Base64UrlUnpadded::encode_string(b)
    }

    /// A flow's first callback passes, the same flow again does not, another flow does; a table full of live flows
    /// refuses new ones (fail closed) and expired ones make room again.
    #[test]
    fn used_flows_once_and_bounded() {
        let f = |state: &str, until: i64| Flow {
            cookie: String::new(),
            state: state.into(),
            nonce: String::new(),
            verifier: String::new(),
            next: String::new(),
            until,
        };
        let u = UsedFlows::default();
        assert!(u.first_use(&f("a", 100), 10));
        assert!(!u.first_use(&f("a", 100), 11));
        assert!(u.first_use(&f("b", 100), 11));
        let full = UsedFlows::default();
        for i in 0..MAX_USED_FLOWS {
            assert!(full.first_use(&f(&i.to_string(), 100), 10));
        }
        assert!(!full.first_use(&f("new", 100), 50), "full of live flows");
        assert!(
            !full.first_use(&f("new", 300), 99),
            "one second before their end, still live"
        );
        assert!(
            full.first_use(&f("new", 300), 100),
            "dead at `until` (as read_flow): dropped"
        );
    }

    /// `header.payload.signature`, the payload being the JSON claims given.
    fn token(claims: &str) -> String {
        format!(
            "{}.{}.{}",
            base64url(br#"{"alg":"none","typ":"JWT"}"#),
            base64url(claims.as_bytes()),
            base64url(b"signature")
        )
    }

    fn claims(f: &Flow, extra: &str) -> String {
        format!(
            r#"{{"iss":"{ISS}","aud":"beastbox-alpha","exp":{},"iat":{NOW},"nonce":"{}","sub":"sub-alice"{extra}}}"#,
            NOW + 300,
            f.nonce
        )
    }

    #[test]
    fn flow_cookie() {
        let (reg, _a, _b) = two_tenants();
        let (a, b) = (reg.by_name("alpha").unwrap(), reg.by_name("beta").unwrap());
        let f = flow(&a);
        // Valid, and read back to the same values.
        assert_eq!(read_flow(&a, &f.cookie, NOW).unwrap(), f);
        assert!(f.cookie.len() <= MAX_COOKIE && f.cookie.starts_with(&format!("{}.", NOW + FLOW_TTL)));
        assert_eq!(read_flow(&a, &f.cookie, NOW + FLOW_TTL - 1).unwrap(), f); // one second before expiry
        assert_eq!(read_flow(&a, &f.cookie, NOW + FLOW_TTL), None); // expired at `until`
        assert_eq!(read_flow(&a, &f.cookie, NOW + FLOW_TTL + 1), None);
        // The other tenant's key never accepts it.
        assert_eq!(read_flow(&b, &f.cookie, NOW), None);
        // One changed byte, anywhere: refused (the MAC covers `until`, `random` and `next`).
        for i in 0..f.cookie.len() {
            let mut bytes = f.cookie.clone().into_bytes();
            bytes[i] = if bytes[i] == b'0' { b'1' } else { b'0' };
            let altered = String::from_utf8(bytes).unwrap();
            assert_eq!(read_flow(&a, &altered, NOW), None, "byte {i}");
        }
        // A cookie the tenant did sign, but whose shape is wrong, is refused as well: the bound on the random part
        // is checked, not assumed from the MAC.
        for (random, ok) in [
            ("a".repeat(63), false),
            ("a".repeat(65), false),
            ("g".repeat(64), false), // not hexadecimal
            ("a".repeat(64), true),
        ] {
            let payload = format!("{}.{random}.", NOW + FLOW_TTL);
            let signed = format!("{payload}.{}", keyed(&a, "oidc-cookie", &payload));
            assert_eq!(read_flow(&a, &signed, NOW).is_some(), ok, "{random:?}");
        }
        // Shape: extra segment, empty part, non-hex random, over-long, a target outside the allowlist.
        let (payload, mac) = f.cookie.rsplit_once('.').unwrap();
        for bad in [
            format!("{}.x", f.cookie),
            format!(".{payload}.{mac}"),
            format!("{payload}."),
            format!("{}.z{}", NOW + FLOW_TTL, payload.split_once('.').unwrap().1),
        ] {
            assert_eq!(read_flow(&a, &bad, NOW), None, "{bad}");
        }
        let long = format!("{}.{}.{}", NOW + FLOW_TTL, "a".repeat(300), mac);
        assert_eq!(read_flow(&a, &long, NOW), None);
        for next in ["https://evil.example", "/web/account2", "//evil.example"] {
            assert_eq!(new_flow(&a, next, NOW), Err(Refusal::Next), "{next}");
        }
        for next in [
            "",
            "/web/account",
            "/index.php/f/12",
            &format!("/index.php/login/v2/flow/{}", "e".repeat(64)),
        ] {
            let f = new_flow(&a, next, NOW).unwrap();
            assert_eq!(f.next, next);
            assert!(f.cookie.len() <= MAX_COOKIE, "{next}");
            assert_eq!(read_flow(&a, &f.cookie, NOW).unwrap(), f);
        }
        // `now + FLOW_TTL` must not overflow: saturated (an absurd clock still gives a valid, short-lived cookie).
        let f = new_flow(&a, "/web/account", i64::MAX - 1).unwrap();
        assert!(f.cookie.starts_with(&format!("{}.", i64::MAX)));
        assert_eq!(read_flow(&a, &f.cookie, i64::MAX - 1).unwrap(), f);
        assert_eq!(read_flow(&a, &f.cookie, i64::MAX), None); // expired at `until`
    }

    #[test]
    fn state_is_keyed_and_compared_in_constant_time() {
        let (reg, _a, _b) = two_tenants();
        let (a, b) = (reg.by_name("alpha").unwrap(), reg.by_name("beta").unwrap());
        let f = flow(&a);
        assert!(state_ok(&f, &f.state));
        assert!(!state_ok(&f, ""));
        let mut altered = f.state.clone();
        altered.replace_range(0..1, if altered.starts_with('0') { "1" } else { "0" });
        assert!(!state_ok(&f, &altered));
        assert!(!state_ok(&f, &f.nonce));
        // Another flow, and another tenant: the same cookie gives different values.
        let g = flow(&a);
        assert_ne!(g.state, f.state);
        assert!(state_ok(&g, &g.state) && !state_ok(&g, &f.state));
        assert_eq!(read_flow(&b, &f.cookie, NOW), None);
    }

    #[test]
    fn authorize_url_carries_every_parameter() {
        let (reg, _a, _b) = two_tenants();
        let a = reg.by_name("alpha").unwrap();
        let f = flow(&a);
        let d = parse_discovery(discovery("").as_bytes(), &client()).unwrap();
        let url = authorize_url(&d, &client(), "https://files.alpha.example", &f);
        assert!(
            url.starts_with("https://auth.example/authorize?response_type=code&"),
            "{url}"
        );
        for part in [
            "response_mode=query",
            "scope=openid",
            "client_id=beastbox-alpha",
            "redirect_uri=https%3A%2F%2Ffiles.alpha.example%2Flogin%2Foidc%2Fcallback",
            &format!("state={}", f.state),
            &format!("nonce={}", f.nonce),
            "code_challenge_method=S256",
        ] {
            assert!(url.contains(part), "{part} missing from {url}");
        }
        let challenge = f.challenge();
        assert!(
            url.contains(&format!("code_challenge={challenge}&code_challenge_method=S256")),
            "{url}"
        );
        // No secret, no verifier: what the browser sees is public.
        assert!(!url.contains(&f.verifier) && !url.contains(&f.cookie));
        // An authorization endpoint that already has a query keeps it.
        let with_query = discovery("").replace("https://auth.example/authorize", "https://auth.example/authorize?a=1");
        let d = parse_discovery(with_query.as_bytes(), &client()).unwrap_or_else(|e| panic!("{e:?}"));
        let url = authorize_url(&d, &client(), "https://files.alpha.example", &f);
        assert!(url.contains("authorize?a=1&response_type=code"), "{url}");
        // PKCE challenge, RFC 7636 appendix B.
        let rfc = Flow {
            cookie: String::new(),
            state: String::new(),
            nonce: String::new(),
            verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".into(),
            next: String::new(),
            until: 0,
        };
        assert_eq!(rfc.challenge(), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        // The value is encoded as a query parameter: no `&` or `#` escapes from it.
        let odd = HttpsUrl::parse("https://auth.example/a?x=1").unwrap();
        assert_eq!(odd.path_and_query, "/a?x=1");
        assert_eq!(encode("a b&c=d"), "a%20b%26c%3Dd");
    }

    #[test]
    fn after_login_allowlist() {
        for ok in [
            "/index.php/f/1",
            "/index.php/f/12345678901234567890",
            "/web/account",
            &format!("/index.php/login/v2/flow/{}", "0123456789abcdef".repeat(4)),
        ] {
            assert_eq!(after_login(ok).as_deref(), Some(ok), "{ok}");
        }
        for bad in [
            "",
            "/",
            "https://evil.example",
            "//evil.example/x",
            "/index.php/f/",
            "/index.php/f/123456789012345678901",
            "/index.php/f/12a",
            "/web/account/2fa",
            "/web/accounts",
            "/index.php/login/v2/flow/",
            "/index.php/login/v2/flow/short",
            "/index.php/login/v2/flow/ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "/index.php/login/v2/flow/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
        ] {
            assert_eq!(after_login(bad), None, "{bad}");
        }
    }

    #[test]
    fn discovery_checks() {
        let c = client();
        let d = parse_discovery(discovery("").as_bytes(), &c).unwrap();
        assert_eq!(d.token_endpoint.host, "auth.example");
        assert_eq!(d.auth, ClientAuth::Basic);
        assert!(!d.iss_parameter);
        // Issuer byte for byte, trailing slash included.
        for (issuer, want) in [
            ("https://auth.example/", Refusal::Issuer),
            ("https://AUTH.example", Refusal::Issuer),
            ("https://other.example", Refusal::Issuer),
        ] {
            let raw = discovery("").replace(ISS, issuer);
            assert_eq!(parse_discovery(raw.as_bytes(), &c).unwrap_err(), want, "{issuer}");
        }
        assert_eq!(
            parse_discovery(
                discovery("").replace(&format!("\"issuer\":\"{ISS}\","), "").as_bytes(),
                &c
            )
            .unwrap_err(),
            Refusal::NotJson
        );
        // Endpoints: `https` only, and the token endpoint on a declared destination.
        for (from, value) in [
            ("https://auth.example/authorize", "http://auth.example/authorize"),
            ("https://auth.example/token", "http://auth.example/token"),
            ("https://auth.example/token", "https://evil.example/token"),
            ("https://auth.example/token", "https://auth.example:8443/token"),
            ("https://auth.example/token", "https://auth.example/token#x"),
        ] {
            let raw = discovery("").replace(from, value);
            assert_eq!(
                parse_discovery(raw.as_bytes(), &c).unwrap_err(),
                Refusal::Endpoint,
                "{value}"
            );
        }
        // A declared back channel host, and the issuer's own port, are accepted.
        let c2 = OidcClient::new(ISS, "id", &["token.auth.example".into(), "auth.example:8443".into()]).unwrap();
        for value in ["https://token.auth.example/token", "https://auth.example:8443/token"] {
            let raw = discovery("").replace("https://auth.example/token", value);
            let d = parse_discovery(raw.as_bytes(), &c2).unwrap_or_else(|e| panic!("{value}: {e:?}"));
            assert_eq!(d.token_endpoint.raw, value);
        }
        // A declared host is not enough on its own: the port has to match too.
        for value in [
            "https://auth.example:8080/token",
            "https://token.auth.example:8443/token",
        ] {
            let raw = discovery("").replace("https://auth.example/token", value);
            assert_eq!(
                parse_discovery(raw.as_bytes(), &c2).unwrap_err(),
                Refusal::Endpoint,
                "{value}"
            );
        }
        // `iss` parameter flag.
        let d = parse_discovery(
            discovery(r#","authorization_response_iss_parameter_supported":true"#).as_bytes(),
            &c,
        )
        .unwrap();
        assert!(d.iss_parameter);
        // Grant: `code` must be offered.
        for (extra, want) in [
            (r#","response_types_supported":["token"]"#, Refusal::GrantType),
            (r#","response_types_supported":[]"#, Refusal::GrantType),
        ] {
            let raw = discovery("").replace(r#""response_types_supported":["code"]"#, &extra[1..]);
            assert_eq!(parse_discovery(raw.as_bytes(), &c).unwrap_err(), want, "{extra}");
        }
        // PKCE: refused only when the methods are listed without S256.
        for (list, ok) in [
            (r#"["S256"]"#, true),
            (r#"["S256","plain"]"#, true),
            (r#"["plain"]"#, false),
            (r#"[]"#, true),
        ] {
            let raw = discovery("").replace(r#"["S256"]"#, list);
            assert_eq!(parse_discovery(raw.as_bytes(), &c).is_ok(), ok, "{list}");
        }
        // Client authentication: basic, otherwise post, otherwise refused.
        for (list, want) in [
            (r#"["client_secret_basic","client_secret_post"]"#, Ok(ClientAuth::Basic)),
            (r#"["client_secret_post"]"#, Ok(ClientAuth::Post)),
            (r#"["private_key_jwt"]"#, Err(Refusal::ClientAuth)),
            (r#"[]"#, Ok(ClientAuth::Basic)),
        ] {
            let raw = discovery("").replace(r#"["client_secret_basic"]"#, list);
            assert_eq!(parse_discovery(raw.as_bytes(), &c).map(|d| d.auth), want, "{list}");
        }
        // Malformed JSON, a duplicate key, an over-long document.
        assert_eq!(parse_discovery(b"{", &c).unwrap_err(), Refusal::NotJson);
        let dup = discovery("").replace(r#""issuer":""#, r#""issuer":"https://other.example","issuer":""#);
        assert_eq!(parse_discovery(dup.as_bytes(), &c).unwrap_err(), Refusal::NotJson);
        // The bound is inclusive: exactly MAX_PROVIDER_JSON bytes is read; one more is refused.
        let mut at = discovery("");
        at.push_str(&" ".repeat(MAX_PROVIDER_JSON - at.len()));
        assert_eq!(at.len(), MAX_PROVIDER_JSON);
        assert!(
            parse_discovery(at.as_bytes(), &c).is_ok(),
            "the bound itself is accepted"
        );
        assert_eq!(
            parse_discovery(format!("{at} ").as_bytes(), &c).unwrap_err(),
            Refusal::TooLarge
        );
    }

    #[test]
    fn token_response_checks() {
        assert_eq!(parse_token_response(br#"{"id_token":"a.b.c"}"#).unwrap(), "a.b.c");
        assert_eq!(
            parse_token_response(br#"{"access_token":"x"}"#).unwrap_err(),
            Refusal::TokenResponse
        );
        assert_eq!(
            parse_token_response(br#"{"error":"invalid_grant"}"#).unwrap_err(),
            Refusal::TokenResponse
        );
        assert_eq!(
            parse_token_response(br#"{"id_token":42}"#).unwrap_err(),
            Refusal::TokenResponse
        );
        assert_eq!(
            parse_token_response(br#"{"id_token":""}"#).unwrap_err(),
            Refusal::TokenResponse
        );
        assert_eq!(
            parse_token_response(br#"{"id_token":"a.b.c","id_token":"d.e.f"}"#).unwrap_err(),
            Refusal::TokenResponse
        );
        assert_eq!(parse_token_response(b"[]").unwrap_err(), Refusal::TokenResponse);
        let long = format!(r#"{{"id_token":"{}"}}"#, "a".repeat(MAX_ID_TOKEN + 1));
        assert_eq!(
            parse_token_response(long.as_bytes()).unwrap_err(),
            Refusal::TokenResponse
        );
        // The bound is inclusive, here too.
        let mut at = String::from(r#"{"id_token":"a.b.c"}"#);
        at.push_str(&" ".repeat(MAX_PROVIDER_JSON - at.len()));
        assert_eq!(parse_token_response(at.as_bytes()).unwrap(), "a.b.c");
        assert_eq!(
            parse_token_response(format!("{at} ").as_bytes()).unwrap_err(),
            Refusal::TooLarge
        );
    }

    #[test]
    fn id_token_checks() {
        let (reg, _a, _b) = two_tenants();
        let a = reg.by_name("alpha").unwrap();
        let f = flow(&a);
        let c = client();
        let ok = token(&claims(&f, ""));
        let v = check_id_token(&ok, &c, &f, NOW).unwrap();
        assert_eq!((v.issuer(), v.subject()), (ISS, "sub-alice"));
        assert!(v.amr().is_empty());
        // A forged header changes nothing: the signature and the header are not used.
        let forged = ok.replacen(
            &base64url(br#"{"alg":"none","typ":"JWT"}"#),
            &base64url(br#"{"alg":"none"}"#),
            1,
        );
        assert!(check_id_token(&forged, &c, &f, NOW).is_ok());
        // A long signature is fine: the bound is 64 KiB, not a few hundred bytes (the segment is not used), and the
        // bound itself is accepted.
        let head = ok.rsplit_once('.').unwrap().0;
        for (len, want_err) in [
            (4096, false),
            (MAX_ID_TOKEN - 1 - head.len(), false),
            (MAX_ID_TOKEN - head.len(), true),
        ] {
            let long = format!("{head}.{}", "s".repeat(len));
            assert_eq!(long.len() > MAX_ID_TOKEN, want_err, "{} bytes", long.len());
            let got = check_id_token(&long, &c, &f, NOW);
            assert_eq!(got.is_err(), want_err, "{} bytes", long.len());
        }
        // Segments.
        for bad in [
            "a.b".to_string(),
            "a.b.c.d".to_string(),
            format!(".{}.{}", base64url(claims(&f, "").as_bytes()), base64url(b"s")),
            format!("{}..{}", base64url(b"{}"), base64url(b"s")),
            "a.b.c.".to_string(),
            format!("{}.!!!.c", base64url(b"{}")),
            format!("{}.{}.c", base64url(b"{}"), base64url(b"not json")),
            format!("{}.{}.", base64url(b"{}"), base64url(br#"["a"]"#)),
            // Valid claims, no signature at all: an empty segment is a refusal, never a pass.
            format!(
                "{}.{}.",
                base64url(br#"{"alg":"none"}"#),
                base64url(claims(&f, "").as_bytes())
            ),
        ] {
            assert_eq!(
                check_id_token(&bad, &c, &f, NOW).unwrap_err(),
                Refusal::IdToken,
                "{bad}"
            );
        }
        // Size bound.
        let big = format!("{}.{}.c", base64url(b"{}"), "a".repeat(MAX_ID_TOKEN));
        assert_eq!(check_id_token(&big, &c, &f, NOW).unwrap_err(), Refusal::TooLarge);
        // `iss`: byte for byte, trailing slash included.
        for iss in ["https://auth.example/", "https://other.example", ""] {
            let t = token(&claims(&f, "").replace(ISS, iss));
            assert_eq!(check_id_token(&t, &c, &f, NOW).unwrap_err(), Refusal::Issuer, "{iss}");
        }
        // `aud`: a string or an array containing the client id; several audiences need `azp`.
        let aud = |v: &str| token(&claims(&f, "").replace(r#""aud":"beastbox-alpha""#, &format!(r#""aud":{v}"#)));
        for (aud_value, want) in [
            (r#""beastbox-alpha""#, Ok(())),
            (r#"["beastbox-alpha"]"#, Ok(())),
            (r#"["beastbox-alpha","other"]"#, Err(Refusal::Audience)), // no `azp`
            (r#"["other"]"#, Err(Refusal::Audience)),
            (r#"[]"#, Err(Refusal::Audience)),
            (r#""other""#, Err(Refusal::Audience)),
            (r#"42"#, Err(Refusal::IdToken)),
        ] {
            let r = check_id_token(&aud(aud_value), &c, &f, NOW).map(|_| ());
            assert_eq!(r, want, "{aud_value}");
        }
        let with_azp = |aud: &str, azp: &str| {
            token(&claims(&f, "").replace(r#""aud":"beastbox-alpha""#, &format!(r#""aud":{aud},"azp":"{azp}""#)))
        };
        assert!(
            check_id_token(
                &with_azp(r#"["beastbox-alpha","other"]"#, "beastbox-alpha"),
                &c,
                &f,
                NOW
            )
            .is_ok()
        );
        assert_eq!(
            check_id_token(&with_azp(r#"["beastbox-alpha","other"]"#, "other"), &c, &f, NOW).unwrap_err(),
            Refusal::Audience
        );
        assert_eq!(
            check_id_token(&with_azp(r#""beastbox-alpha""#, "other"), &c, &f, NOW).unwrap_err(),
            Refusal::Audience
        );
        // `exp`: refused at now - 60 and below, accepted one second later.
        let exp = |v: &str| token(&claims(&f, "").replace(&format!("\"exp\":{}", NOW + 300), &format!("\"exp\":{v}")));
        assert!(check_id_token(&exp(&format!("{}", NOW - SKEW + 1)), &c, &f, NOW).is_ok());
        for v in [NOW - SKEW, NOW - SKEW - 1, 0, -1] {
            assert_eq!(
                check_id_token(&exp(&format!("{v}")), &c, &f, NOW).unwrap_err(),
                Refusal::Expired,
                "{v}"
            );
        }
        // A number outside what can be a date is refused, never read as "never expires"; `1e999` is not even an f64.
        for (v, want) in [
            ("1e300", Refusal::Expired),
            ("-1e300", Refusal::Expired),
            ("1e999", Refusal::IdToken),
        ] {
            assert_eq!(check_id_token(&exp(v), &c, &f, NOW).unwrap_err(), want, "{v}");
        }
        // A decimal is read as the second it names.
        assert!(check_id_token(&exp(&format!("{}.5", NOW + 1)), &c, &f, NOW).is_ok());
        assert_eq!(
            check_id_token(&exp(r#""soon""#), &c, &f, NOW).unwrap_err(),
            Refusal::IdToken
        );
        // `iat`: 60 s ahead at most, 600 s behind at most.
        let iat = |v: &str| token(&claims(&f, "").replace(&format!("\"iat\":{NOW}"), &format!("\"iat\":{v}")));
        for (v, ok) in [
            (NOW + SKEW, true),
            (NOW + SKEW + 1, false),
            (NOW - 600, true),
            (NOW - 601, false),
        ] {
            assert_eq!(check_id_token(&iat(&format!("{v}")), &c, &f, NOW).is_ok(), ok, "{v}");
        }
        assert!(
            check_id_token(
                &token(&claims(&f, "").replace(&format!(r#","iat":{NOW}"#), "")),
                &c,
                &f,
                NOW
            )
            .is_ok()
        );
        // `nonce`: equal in constant time, present.
        for (v, want) in [
            (format!(r#""{}""#, f.nonce), Ok(())),
            (r#""other""#.to_string(), Err(Refusal::Nonce)),
            ("null".to_string(), Err(Refusal::Nonce)),
        ] {
            let t = token(&claims(&f, "").replace(&format!(r#""nonce":"{}""#, f.nonce), &format!(r#""nonce":{v}"#)));
            assert_eq!(check_id_token(&t, &c, &f, NOW).map(|_| ()), want, "{v}");
        }
        let other = flow(&a);
        assert_eq!(check_id_token(&ok, &c, &other, NOW).unwrap_err(), Refusal::Nonce);
        // `sub`: 1 to 255 visible ASCII characters.
        let sub = |v: &str| token(&claims(&f, "").replace("sub-alice", v));
        assert!(check_id_token(&sub(&"s".repeat(255)), &c, &f, NOW).is_ok());
        // `a\u0007` is the JSON escape of a control character: it decodes to one, and must be refused as a subject.
        for bad in ["", &"s".repeat(256), "a b", "a\\u0007", "é"] {
            assert_eq!(
                check_id_token(&sub(bad), &c, &f, NOW).unwrap_err(),
                Refusal::Subject,
                "{bad:?}"
            );
        }
        // `amr`: an optional array of visible ASCII values of at most 32 bytes each (the bound itself is accepted).
        for (v, ok) in [
            (r#"["mfa"]"#, true),
            (r#"["mfa","pwd"]"#, true),
            (r#"[]"#, true),
            (r#"[""]"#, false),
            (r#""mfa""#, false),
            (r#"["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]"#, true),
            (r#"["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]"#, false),
            (r#"["a b"]"#, false),
            (r#"["ab"]"#, false),
        ] {
            let t = token(&claims(&f, &format!(r#","amr":{v}"#)));
            assert_eq!(check_id_token(&t, &c, &f, NOW).is_ok(), ok, "{v}");
        }
        let t = token(&claims(&f, r#","amr":["mfa"]"#));
        assert_eq!(check_id_token(&t, &c, &f, NOW).unwrap().amr(), ["mfa"]);
        // Whole seconds, and the numeric guard: 9e15 is the bound (read), above it and the infinite forms are
        // refused, never rounded into something valid.
        for (exp, ok) in [("9e15", true), ("9.1e15", false), ("1e999", false)] {
            let raw = claims(&f, "").replace(&format!("\"exp\":{}", NOW + 300), &format!("\"exp\":{exp}"));
            let got = check_id_token(&token(&raw), &c, &f, NOW);
            assert_eq!(got.is_ok(), ok, "exp {exp}");
        }
        // Duplicate claims: the derived struct refuses them.
        let dup = claims(&f, "").replacen(r#""iss""#, r#""iss":"https://evil.example","iss""#, 1);
        assert_eq!(check_id_token(&token(&dup), &c, &f, NOW).unwrap_err(), Refusal::IdToken);
    }

    proptest::proptest! {
        /// Accepted: reparses from `raw` to the same value and keeps its shape. Refused: no panic.
        #[test]
        fn parse_never_panics_and_round_trips(a in "[ -~]{0,80}", b in proptest::prelude::any::<String>()) {
            for s in [a.as_str(), b.as_str()] {
                let Ok(u) = HttpsUrl::parse(s) else { continue };
                proptest::prop_assert_eq!(u.raw.as_str(), s);
                proptest::prop_assert!(u.raw.len() <= MAX_URL && u.port != 0);
                proptest::prop_assert!(u.host.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-'));
                proptest::prop_assert_eq!(HttpsUrl::parse(&u.raw), Ok(u));
            }
        }

        /// Any text as a flow cookie, a token response or an `id_token`: no panic, and nothing accepted that the checks
        /// would not accept from a valid fixture.
        #[test]
        fn client_values_never_panic(s in proptest::prelude::any::<String>()) {
            let (reg, _a, _b) = two_tenants();
            let a = reg.by_name("alpha").unwrap();
            let c = client();
            let f = flow(&a);
            if let Some(read) = read_flow(&a, &s, NOW) {
                // Accepted only with the default target ("") or one the allowlist accepts, and a life of at most 600 s.
                let target = read.next.clone();
                let again = after_login(&target);
                proptest::prop_assert!(target.is_empty() || again.as_deref() == Some(target.as_str()));
                proptest::prop_assert!(read.cookie.len() <= MAX_COOKIE);
                proptest::prop_assert!(!read.state.is_empty() && !read.verifier.is_empty());
            }
            let _ = parse_token_response(s.as_bytes());
            if let Ok(_v) = check_id_token(&s, &c, &f, NOW) {
                // Whatever passed carries a subject the check accepts.
                proptest::prop_assert!(valid_subject(_v.subject()));
            }
            let _ = parse_discovery(s.as_bytes(), &c);
        }

        /// A changed byte of the cookie never gives the same `state`, and a flow of one tenant never validates on the
        /// other.
        #[test]
        fn cookie_bytes_and_tenants_are_bound(i in 0usize..80) {
            let (reg, _a, _b) = two_tenants();
            let (a, b) = (reg.by_name("alpha").unwrap(), reg.by_name("beta").unwrap());
            let f = flow(&a);
            proptest::prop_assert_eq!(read_flow(&b, &f.cookie, NOW), None);
            if i < f.cookie.len() {
                let mut bytes = f.cookie.clone().into_bytes();
                bytes[i] = if bytes[i] == b'0' { b'1' } else { b'0' };
                let altered = String::from_utf8(bytes).unwrap();
                if let Some(g) = read_flow(&a, &altered, NOW) {
                    proptest::prop_assert_ne!(g.state, f.state);
                    proptest::prop_assert_ne!(g.nonce, f.nonce);
                }
            }
        }

        /// `after_login` output is empty or inside the allowlist, whatever the input.
        #[test]
        fn after_login_is_bounded(v in proptest::prelude::any::<String>()) {
            if let Some(ok) = after_login(&v) {
                proptest::prop_assert_eq!(&ok, &v);
                proptest::prop_assert!(
                    v == "/web/account"
                        || v.starts_with("/index.php/f/")
                        || v.starts_with("/index.php/login/v2/flow/")
                );
            }
        }
    }
}
