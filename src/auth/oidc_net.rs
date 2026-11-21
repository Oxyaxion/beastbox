//! OIDC back channel (phase 5): the network side of the OIDC client. The protocol checks stay in `oidc.rs`
//! (pure, tested); this module only moves bytes — verified TLS, bounded bodies, timeouts, and every
//! connection through the `Net` channel: direct in tests (before Capsicum), the Casper `system.net`
//! channel in production (ADR-6), limited to the configured destinations.
//!
//! The `base` of `redirect_uri` comes from the configuration (`OidcRuntime::base`, the tenant's first exact
//! host), never from the request's `Host` header: a forged header must not reopen `redirect_uri` (§4.1).

use super::oidc::{self, ClientAuth, Discovery, Flow, HttpsUrl, Refusal};
use crate::config::OidcRuntime;
use crate::fs::CasperNet;
use base64ct::Encoding;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use rustls_pki_types::pem::PemObject;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// Whole back-channel call timeout (DNS + TCP + TLS + HTTP).
const CALL_TIMEOUT: Duration = Duration::from_secs(15);
/// TCP connect timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The outgoing channel of the back channel.
pub enum Net {
    /// Direct TCP (tests, development without Capsicum).
    Direct,
    /// The Casper `system.net` channel (production, after `cap_enter()`).
    Casper(Arc<CasperNet>),
}

impl Net {
    /// The channel the server needs: Casper (opened now, before `cap_enter()`) when at least one tenant has
    /// `[tenant.oidc]` — fail closed if the service or its limits cannot be had; direct otherwise (no OIDC,
    /// nothing to reach).
    pub fn for_tenants(tenants: &[&crate::tenant::TenantCtx]) -> crate::Result<Net> {
        let mut resolvable: Vec<(String, u16)> = Vec::new();
        let mut fixed: Vec<SocketAddr> = Vec::new();
        let mut any = false;
        for t in tenants {
            if let Some(o) = t.oidc() {
                any = true;
                resolvable.extend(o.resolvable());
                if let Some(a) = o.connect_addr {
                    fixed.push(a);
                }
            }
        }
        if !any {
            return Ok(Net::Direct);
        }
        let net = CasperNet::open(&resolvable, &fixed)
            .map_err(|e| crate::Error::Config(format!("oidc: Casper channel: {e}")))?;
        Ok(Net::Casper(Arc::new(net)))
    }

    /// Resolves `host` (through the Casper service when `Net::Casper`). Blocking: called from a blocking
    /// thread (`resolve_async` does it).
    fn resolve_blocking(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        match self {
            Net::Direct => {
                use std::net::ToSocketAddrs;
                Ok((host, port).to_socket_addrs()?.collect())
            }
            Net::Casper(c) => c.resolve(host, port),
        }
    }

    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let h = host.to_string();
        match self {
            Net::Direct => tokio::task::spawn_blocking(move || Net::Direct.resolve_blocking(&h, port))
                .await
                .map_err(|e| io::Error::other(e.to_string()))
                .and_then(|r| r),
            Net::Casper(c) => {
                let c = c.clone();
                tokio::task::spawn_blocking(move || c.resolve(&h, port))
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))
                    .and_then(|r| r)
            }
        }
    }

    /// One TCP connection to the URL's host (or to `connect_addr` when set — the name is still used for TLS
    /// SNI and the `Host` header, so the certificate is checked against the configured name).
    async fn tcp(&self, host: &str, port: u16, connect_addr: Option<SocketAddr>) -> io::Result<tokio::net::TcpStream> {
        let addrs = match connect_addr {
            Some(a) => vec![a],
            None => self.resolve(host, port).await?,
        };
        let mut last = io::Error::other("no address");
        for a in addrs {
            match self {
                Net::Direct => match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(a)).await {
                    Ok(Ok(s)) => return Ok(s),
                    Ok(Err(e)) => last = e,
                    Err(_) => last = io::Error::from(io::ErrorKind::TimedOut),
                },
                Net::Casper(c) => {
                    let c = c.clone();
                    let r = tokio::task::spawn_blocking(move || c.connect(a))
                        .await
                        .map_err(|e| io::Error::other(e.to_string()));
                    match r
                        .and_then(|r| r)
                        .and_then(|fd| tokio::net::TcpStream::from_std(fd.into()))
                    {
                        // The connection is in progress (non-blocking socket): wait for it here, bounded.
                        Ok(s) => match tokio::time::timeout(CONNECT_TIMEOUT, s.writable()).await {
                            Ok(Ok(())) => match s.take_error() {
                                Ok(None) => return Ok(s),
                                Ok(Some(e)) | Err(e) => last = e,
                            },
                            Ok(Err(e)) => last = e,
                            Err(_) => last = io::Error::from(io::ErrorKind::TimedOut),
                        },
                        Err(e) => last = e,
                    }
                }
            }
        }
        Err(last)
    }
}

/// A TLS client with no root at all, for the tests that never reach the network (the login page of a tenant with a
/// provider).
#[cfg(test)]
pub(crate) fn test_tls() -> std::sync::Arc<rustls::ClientConfig> {
    std::sync::Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
    )
}

/// The rustls client config: the configured CA file only (a private CA, or the system bundle), TLS 1.2+,
/// ALPN `http/1.1`. No client certificate. Called **once at startup** (`OidcRuntime::build`): it reads an
/// absolute path, which capability mode forbids (`ECAPMODE`).
pub fn tls_config(ca_file: &Path) -> io::Result<rustls::ClientConfig> {
    let pem = std::fs::read(ca_file).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", ca_file.display())))?;
    let mut roots = rustls::RootCertStore::empty();
    let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pki_types::CertificateDer::pem_slice_iter(pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", ca_file.display())))?;
    if certs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: no certificate", ca_file.display()),
        ));
    }
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: no usable root CA", ca_file.display()),
        ));
    }
    let mut c = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(c)
}

/// One HTTPS request to `url` (host and port of the URL; `connect_addr` overrides the address only),
/// with optional form body and extra headers. Returns the bounded body. `Refusal::Endpoint`/`TokenResponse`
/// on any failure — the browser never sees the detail.
async fn https(
    net: &Net,
    o: &OidcRuntime,
    url: &HttpsUrl,
    method: &str,
    form: Option<String>,
    extra: &[(&str, String)],
) -> Result<Vec<u8>, Refusal> {
    let host = url.host.clone();
    let port = url.port;
    let tls = o.tls.clone();
    let r = tokio::time::timeout(CALL_TIMEOUT, async {
        let tcp = net.tcp(&host, port, o.connect_addr).await.map_err(|e| {
            tracing::warn!("oidc: tcp {host}:{port}: {e}");
            Refusal::Endpoint
        })?;
        let name = rustls_pki_types::ServerName::try_from(host.clone()).map_err(|_| Refusal::Endpoint)?;
        let tls = tokio_rustls::TlsConnector::from(tls)
            .connect(name, tcp)
            .await
            .map_err(|e| {
                tracing::warn!("oidc: tls {host}: {e}");
                Refusal::Endpoint
            })?;
        let (mut send, conn) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
            .await
            .map_err(|e| {
                tracing::warn!("oidc: http handshake: {e}");
                Refusal::Endpoint
            })?;
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("oidc: connection closed: {e}");
            }
        });
        let host_header = if port == 443 {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        // Origin-form request line (the Host header carries the authority), as a direct HTTP/1.1 server expects.
        let target = if url.path_and_query.is_empty() {
            "/"
        } else {
            url.path_and_query.as_str()
        };
        let mut b = hyper::Request::builder()
            .method(method)
            .uri(target)
            .header("host", &host_header)
            .header("accept", "application/json")
            .header("user-agent", concat!("beastbox/", env!("CARGO_PKG_VERSION")));
        let body = match form {
            Some(f) => {
                b = b
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("content-length", f.len().to_string());
                Bytes::from(f)
            }
            None => Bytes::new(),
        };
        for (k, v) in extra {
            b = b.header(*k, v);
        }
        let req = b.body(Full::new(body)).map_err(|_| Refusal::Endpoint)?;
        let res = send.send_request(req).await.map_err(|e| {
            tracing::warn!("oidc: request: {e}");
            Refusal::Endpoint
        })?;
        let status = res.status();
        let limited = Limited::new(res.into_body(), oidc::MAX_PROVIDER_JSON_BYTES + 1);
        let bytes = limited
            .collect()
            .await
            .map_err(|e| {
                tracing::warn!("oidc: response body: {e}");
                Refusal::TooLarge
            })?
            .to_bytes();
        if bytes.len() > oidc::MAX_PROVIDER_JSON_BYTES {
            return Err(Refusal::TooLarge);
        }
        if status != hyper::StatusCode::OK {
            tracing::warn!("oidc: {method} {host}{}: status {status}", url.path_and_query);
            return Err(Refusal::Endpoint);
        }
        Ok(bytes.to_vec())
    })
    .await;
    r.unwrap_or(Err(Refusal::Endpoint))
}

/// The discovery document (`GET <issuer>/.well-known/openid-configuration`), checked by `parse_discovery`.
pub async fn fetch_discovery(net: &Net, o: &OidcRuntime) -> Result<Discovery, Refusal> {
    let mut url = o.client.issuer.raw.trim_end_matches('/').to_string();
    url.push_str("/.well-known/openid-configuration");
    let url = HttpsUrl::parse(&url).map_err(|_| Refusal::Endpoint)?;
    let body = https(net, o, &url, "GET", None, &[]).await?;
    oidc::parse_discovery(&body, &o.client)
}

/// The token exchange (`POST` the token endpoint, authorization code + PKCE verifier, client authentication
/// per the discovery document). Returns the `id_token` only (`parse_token_response`).
pub async fn exchange_code(net: &Net, o: &OidcRuntime, d: &Discovery, code: &str, f: &Flow) -> Result<String, Refusal> {
    let redirect = format!("{}/login/oidc/callback", o.base);
    let enc = |v: &str| oidc::encode_query(v);
    let mut form = format!(
        "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
        enc(code),
        enc(&redirect),
        enc(&o.client.client_id),
        enc(&f.verifier)
    );
    let mut extra: Vec<(&str, String)> = Vec::new();
    match d.auth {
        ClientAuth::Basic => {
            // RFC 6749 §2.3.1: both values form-encoded before base64 (a `:` or `%` in the secret stays itself).
            let raw = format!("{}:{}", enc(&o.client.client_id), enc(&o.secret));
            extra.push((
                "authorization",
                format!("Basic {}", base64ct::Base64::encode_string(raw.as_bytes())),
            ));
        }
        ClientAuth::Post => {
            form.push_str(&format!("&client_secret={}", enc(&o.secret)));
        }
    }
    let body = https(net, o, &d.token_endpoint, "POST", Some(form), &extra)
        .await
        .map_err(|r| match r {
            Refusal::Endpoint | Refusal::TooLarge => Refusal::TokenResponse,
            other => other,
        })?;
    oidc::parse_token_response(&body)
}

#[cfg(test)]
mod tests {
    use super::super::oidc::OidcClient;
    use super::*;

    #[test]
    fn well_known_url_of_an_issuer_with_a_path() {
        let o = || OidcRuntime {
            client: OidcClient::new("https://auth.example/application/o/alpha/", "c", &[]).unwrap(),
            secret: "s".into(),
            second_factor: crate::config::SecondFactor::Beastbox,
            required_amr: vec!["mfa".into()],
            connect_addr: None,
            tls: test_tls(),
            base: "https://files.alpha.example".into(),
            password_login: false,
            discovery: std::sync::Mutex::new(None),
        };
        let u = o();
        let mut url = u.client.issuer.raw.trim_end_matches('/').to_string();
        url.push_str("/.well-known/openid-configuration");
        assert_eq!(
            url,
            "https://auth.example/application/o/alpha/.well-known/openid-configuration"
        );
        let parsed = HttpsUrl::parse(&url).unwrap();
        assert_eq!(parsed.host, "auth.example");
        assert_eq!(
            parsed.path_and_query,
            "/application/o/alpha/.well-known/openid-configuration"
        );
        // The plain issuer too.
        let u = OidcRuntime {
            client: OidcClient::new("https://auth.example", "c", &[]).unwrap(),
            ..o()
        };
        let mut url = u.client.issuer.raw.trim_end_matches('/').to_string();
        url.push_str("/.well-known/openid-configuration");
        assert_eq!(url, "https://auth.example/.well-known/openid-configuration");
    }

    /// The CA file is read and checked at every call: a missing, empty or garbage file is refused (fail closed
    /// before any connection), a valid bundle is accepted.
    #[test]
    fn tls_config_checks_the_ca_file() {
        let d = tempfile::tempdir().unwrap();
        let missing = d.path().join("nope.pem");
        assert!(tls_config(&missing).is_err());
        let empty = d.path().join("empty.pem");
        std::fs::write(&empty, b"").unwrap();
        let e = tls_config(&empty).unwrap_err();
        assert!(e.to_string().contains("no certificate"), "{e}");
        let garbage = d.path().join("garbage.pem");
        std::fs::write(&garbage, b"not a pem at all").unwrap();
        assert!(tls_config(&garbage).is_err());
        // A PEM block that is not a certificate either.
        let key = d.path().join("key.pem");
        std::fs::write(&key, b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n").unwrap();
        assert!(tls_config(&key).is_err());
        // A real certificate (self-signed CA) is accepted.
        let ca = d.path().join("ca.pem");
        let s = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                d.path().join("k.pem").to_str().unwrap(),
                "-out",
                ca.to_str().unwrap(),
                "-days",
                "1",
                "-subj",
                "/CN=t",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
            ])
            .output()
            .unwrap();
        assert!(s.status.success(), "{}", String::from_utf8_lossy(&s.stderr));
        let c = tls_config(&ca).unwrap();
        assert_eq!(c.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    /// The channel the server opens at startup: `Direct` when no tenant has `[tenant.oidc]` (nothing to reach);
    /// with an OIDC tenant, the Casper channel — which fails closed when the `system.net` service cannot be
    /// opened or its limits read back.
    #[test]
    fn net_for_tenants_picks_the_channel() {
        // The channel forks a Casper service: run it in a process of its own (see `fs::forked_elsewhere`).
        if crate::fs::forked_elsewhere("auth::oidc_net::tests::net_for_tenants_picks_the_channel") {
            return;
        }
        let (reg, _a, _b) = crate::tenant::tests::two_tenants();
        let refs: Vec<&crate::tenant::TenantCtx> = reg.all().iter().collect();
        assert!(matches!(Net::for_tenants(&refs).unwrap(), Net::Direct));
        let o = OidcRuntime {
            client: OidcClient::new("https://auth.example", "c", &["auth.example".to_string()]).unwrap(),
            secret: "s".into(),
            second_factor: crate::config::SecondFactor::Beastbox,
            required_amr: vec![],
            connect_addr: None,
            tls: test_tls(),
            base: "https://files.alpha.example".into(),
            password_login: false,
            discovery: std::sync::Mutex::new(None),
        };
        let (reg2, _a, _b) = crate::tenant::tests::two_tenants_with(Some(o), None);
        let refs: Vec<&crate::tenant::TenantCtx> = reg2.all().iter().collect();
        match Net::for_tenants(&refs) {
            Ok(Net::Casper(_)) => {} // the channel opened with its limits: the real path of `serve`.
            Ok(Net::Direct) => panic!("an OIDC tenant must not fall back to direct TCP"),
            Err(e) => assert!(e.to_string().contains("Casper"), "{e}"),
        }
    }

    /// The Casper channel connects without blocking (the service answers `EINPROGRESS`): the socket is waited for here,
    /// a live listener gives a usable stream, a closed port an error — never a stream that is not connected.
    #[test]
    fn casper_tcp_waits_for_the_connection() {
        if crate::fs::forked_elsewhere("auth::oidc_net::tests::casper_tcp_waits_for_the_connection") {
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed_port = closed.local_addr().unwrap().port();
        drop(closed);
        let net = Net::Casper(Arc::new(
            CasperNet::open(&[("localhost".into(), port), ("localhost".into(), closed_port)], &[]).unwrap(),
        ));
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut s = net.tcp("localhost", port, None).await.unwrap();
            s.write_all(b"ping").await.unwrap();
            let (mut peer, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4];
            std::io::Read::read_exact(&mut peer, &mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            std::io::Write::write_all(&mut peer, b"pong").unwrap();
            s.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"pong");
            assert!(net.tcp("localhost", closed_port, None).await.is_err());
        });
    }

    /// The direct channel resolves a real name and refuses one that does not exist: the address list is never
    /// silently empty.
    #[test]
    fn direct_resolve_returns_addresses() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // Both entry points (the blocking one and the async wrapper) hand a real list back.
        for addrs in [
            Net::Direct.resolve_blocking("localhost", 443).unwrap(),
            rt.block_on(Net::Direct.resolve("localhost", 443)).unwrap(),
        ] {
            assert!(!addrs.is_empty(), "{addrs:?}");
        }
        assert!(Net::Direct.resolve_blocking("example.invalid", 443).is_err());
        assert!(rt.block_on(Net::Direct.resolve("example.invalid", 443)).is_err());
    }

    #[test]
    fn token_form_carries_every_field() {
        // The form built by exchange_code, without the network: same fields, Basic vs Post.
        let enc = |v: &str| oidc::encode_query(v);
        let redirect = "https://files.alpha.example/login/oidc/callback";
        let mut form = format!(
            "grant_type=authorization_code&code={}&redirect_uri={}&client_id={}&code_verifier={}",
            enc("code 1&2"),
            enc(redirect),
            enc("beastbox-alpha"),
            enc("verifier+x/y")
        );
        assert!(form.contains("code=code%201%262"));
        assert!(form.contains("redirect_uri=https%3A%2F%2Ffiles.alpha.example%2Flogin%2Foidc%2Fcallback"));
        assert!(form.contains("code_verifier=verifier%2Bx%2Fy"));
        form.push_str(&format!("&client_secret={}", enc("sec:ret")));
        assert!(form.contains("client_secret=sec%3Aret"));
    }
}
