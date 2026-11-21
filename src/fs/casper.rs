//! Casper channel for the OIDC back channel (ADR-6, §0.3). After `cap_enter()`, the kernel refuses every
//! outgoing connection (`ECAPMODE`), so all of Beastbox's go through the system's `system.net` Casper
//! service — **limited at startup to the configured destinations** (the issuer and the declared back channel
//! hosts for name resolution, plus `connect_addr` when set for fixed endpoints).
//!
//! `socket(2)` is allowed in capability mode, `connect(2)` is not: each outgoing connection opens its own
//! socket and hands it to the service (`cap_connect`), which makes the connection if the address is on the
//! allowlist and refuses it otherwise.
//!
//! No daemon to install: `libcasper` (base system, with `libcap_net` and `libnv`) starts the service itself as
//! a forked child of the process. All the FFI of the project lives in this module (with `fs/`), the only place
//! allowed to use `unsafe`.

use std::ffi::{CString, c_char, c_int};
use std::io;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Mutex;

// ---- opaque Casper / nvlist types (libcasper, libnv) ----
#[allow(non_camel_case_types)]
enum cap_channel_t {}
#[allow(non_camel_case_types)]
enum nvlist_t {}
#[allow(non_camel_case_types)]
enum cap_net_limit_t {}

#[link(name = "casper")]
unsafe extern "C" {
    fn cap_init() -> *mut cap_channel_t;
    fn cap_service_open(chan: *mut cap_channel_t, name: *const c_char) -> *mut cap_channel_t;
    fn cap_close(chan: *mut cap_channel_t) -> c_int;
    fn cap_limit_get(chan: *mut cap_channel_t, limitsp: *mut *mut nvlist_t) -> c_int;
}

#[link(name = "cap_net")]
unsafe extern "C" {
    fn cap_net_limit_init(chan: *mut cap_channel_t, mode: u64) -> *mut cap_net_limit_t;
    fn cap_net_limit_name2addr(
        limit: *mut cap_net_limit_t,
        host: *const c_char,
        serv: *const c_char,
    ) -> *mut cap_net_limit_t;
    fn cap_net_limit_connect(
        limit: *mut cap_net_limit_t,
        sa: *const libc::sockaddr,
        salen: libc::socklen_t,
    ) -> *mut cap_net_limit_t;
    fn cap_net_limit(limit: *mut cap_net_limit_t) -> c_int;
    /// Connects `s` through the service, which checks it against the channel's limits. The descriptor keeps
    /// its rights on this side: nothing is moved to the service but a `dup` of it.
    fn cap_connect(chan: *mut cap_channel_t, s: c_int, name: *const libc::sockaddr, namelen: libc::socklen_t) -> c_int;
    fn cap_getaddrinfo(
        chan: *mut cap_channel_t,
        host: *const c_char,
        serv: *const c_char,
        hints: *const libc::addrinfo,
        res: *mut *mut libc::addrinfo,
    ) -> c_int;
}

// libnv exports its symbols with the `FreeBSD_` prefix (symbol versioning): link them by that name.
#[link(name = "nv")]
unsafe extern "C" {
    #[link_name = "FreeBSD_nvlist_destroy"]
    fn nvlist_destroy(nvl: *mut nvlist_t);
    #[link_name = "FreeBSD_nvlist_exists"]
    fn nvlist_exists(nvl: *const nvlist_t, name: *const c_char) -> bool;
    /// `uint64_t nvlist_get_number(const nvlist_t *, const char *)`: returns the number itself (libnv has no
    /// out-parameter), so the C prototype must be copied exactly.
    #[link_name = "FreeBSD_nvlist_get_number"]
    fn nvlist_get_number(nvl: *const nvlist_t, name: *const c_char) -> u64;
}

/// Mode bits of `cap_net` (cap_net.h): resolve the allowed names, connect (fixed allowlist and addresses
/// obtained through those resolutions — the split DNS case).
const CAPNET_NAME2ADDR: u64 = 0x02;
const CAPNET_CONNECT: u64 = 0x10;
const CAPNET_CONNECTDNS: u64 = 0x40;

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn err(context: &str) -> io::Error {
    let e = io::Error::last_os_error();
    io::Error::new(e.kind(), format!("casper {context}: {e}"))
}

/// The `system.net` channel, with its destination allowlist.
/// All access serialized: a `cap_channel_t` is not thread-safe (one request per channel at a time).
pub struct CasperNet {
    inner: Mutex<Inner>,
}

struct Inner {
    chan: *mut cap_channel_t,
    net: *mut cap_channel_t,
}

// SAFETY: the raw casper pointers are only used under the mutex, and the service owns the other end.
unsafe impl Send for Inner {}
// SAFETY: same.
unsafe impl Sync for Inner {}

impl std::fmt::Debug for CasperNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CasperNet").finish_non_exhaustive()
    }
}

impl CasperNet {
    /// Opens `system.net` and sets the limits **before** they can be used: `resolvable` are the
    /// `(host, port)` the service may resolve, `connect_addrs` the fixed endpoints it may connect to
    /// (`connect_addr`). Without a fixed endpoint `CAPNET_CONNECT` is not set at all — with an empty list it
    /// means "anywhere" — and `CAPNET_CONNECTDNS` allows connecting only to addresses the service itself
    /// resolved from the allowed names. Startup only, fail closed.
    pub fn open(resolvable: &[(String, u16)], connect_addrs: &[SocketAddr]) -> io::Result<Self> {
        // SAFETY: plain FFI calls, checked for null / error returns.
        unsafe {
            let chan = cap_init();
            if chan.is_null() {
                return Err(err("cap_init (no libcasper service?)"));
            }
            let name = cstr("system.net")?;
            let net = cap_service_open(chan, name.as_ptr());
            if net.is_null() {
                cap_close(chan);
                return Err(io::Error::other(
                    "casper: service system.net unavailable (libcasper missing from the base system?)",
                ));
            }
            if let Err(e) = Self::limit(net, resolvable, connect_addrs) {
                cap_close(net);
                cap_close(chan);
                return Err(e);
            }
            Ok(Self {
                inner: Mutex::new(Inner { chan, net }),
            })
        }
    }

    /// Sets the limits and checks them back (`cap_limit_get`): the startup check that they are in place
    /// (the service refuses to widen them afterwards).
    fn limit(net: *mut cap_channel_t, resolvable: &[(String, u16)], connect_addrs: &[SocketAddr]) -> io::Result<()> {
        // SAFETY: `net` is a valid channel from cap_init/cap_service_open; the nvlist calls get valid C
        // strings and buffers; `got` is destroyed on every path.
        unsafe {
            // `CAPNET_CONNECT` with an empty list means "connect anywhere": only set it when a fixed endpoint
            // is declared. Without one, `CAPNET_CONNECTDNS` restricts the connections to the addresses the
            // service itself resolved from the allowed names (measured on 15.1).
            let mode = CAPNET_NAME2ADDR | CAPNET_CONNECTDNS | if connect_addrs.is_empty() { 0 } else { CAPNET_CONNECT };
            // The limits belong to the service channel itself (`cap_net_limit_init(net, …)`): on the casper
            // channel, `cap_net_limit` answers EINVAL and `serve` would refuse to start.
            let limit = cap_net_limit_init(net, mode);
            if limit.is_null() {
                return Err(err("cap_net_limit_init"));
            }
            for (host, port) in resolvable {
                let h = cstr(host)?;
                let s = cstr(&port.to_string())?;
                cap_net_limit_name2addr(limit, h.as_ptr(), s.as_ptr());
            }
            for a in connect_addrs {
                let (sa, len) = sockaddr_bytes(a);
                cap_net_limit_connect(limit, sa.as_ptr() as *const libc::sockaddr, len);
            }
            // `cap_net_limit` consumes (frees) `limit` on every path: do not call `cap_net_free` after it.
            if cap_net_limit(limit) != 0 {
                return Err(err("cap_net_limit"));
            }
            // Read the limits back: they must be the ones just set.
            let mut got: *mut nvlist_t = std::ptr::null_mut();
            if cap_limit_get(net, &mut got) != 0 || got.is_null() {
                return Err(err("cap_limit_get"));
            }
            // `name2addr` is always present (the issuer); `connect` only when a fixed endpoint was declared.
            let ok = nvlist_exists(got, c"name2addr".as_ptr())
                && (connect_addrs.is_empty() || nvlist_exists(got, c"connect".as_ptr()));
            let mode_ok = nvlist_get_number(got, c"mode".as_ptr()) & mode == mode;
            nvlist_destroy(got);
            if !ok || !mode_ok {
                return Err(io::Error::other(
                    "casper: system.net limits not as configured (refusing to start with an open channel)",
                ));
            }
            tracing::info!(
                "casper: system.net limited to {} resolvable host(s), {} fixed endpoint(s)",
                resolvable.len(),
                connect_addrs.len()
            );
            Ok(())
        }
    }

    /// Resolves `host` through the service (only the allowed names pass the limit).
    pub fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let h = cstr(host)?;
        let s = cstr(&port.to_string())?;
        let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
        hints.ai_family = libc::AF_UNSPEC;
        hints.ai_socktype = libc::SOCK_STREAM;
        let mut res: *mut libc::addrinfo = std::ptr::null_mut();
        let inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("casper: lock poisoned"))?;
        // SAFETY: `net` is a valid channel, buffers are valid; `res` is freed below on every path.
        let r = unsafe { cap_getaddrinfo(inner.net, h.as_ptr(), s.as_ptr(), &hints, &mut res) };
        if r != 0 {
            return Err(io::Error::other(format!("casper getaddrinfo {host}:{port}: error {r}")));
        }
        let mut out = Vec::new();
        let mut p = res;
        while !p.is_null() {
            let ai = unsafe { &*p };
            if !ai.ai_addr.is_null() {
                let sa = unsafe { &*(ai.ai_addr as *const libc::sockaddr) };
                if let Some(a) = sockaddr_of(sa, ai.ai_addrlen) {
                    out.push(a);
                }
            }
            p = ai.ai_next;
        }
        unsafe { libc::freeaddrinfo(res) };
        if out.is_empty() {
            return Err(io::Error::other(format!(
                "casper getaddrinfo {host}:{port}: no address"
            )));
        }
        Ok(out)
    }

    /// Starts a connection to `addr` through the service, which enforces the allowlist. `socket(2)` is allowed in
    /// capability mode (only `connect(2)` is not), so each call opens its own socket, used and closed. The socket is
    /// non-blocking: the service's `connect` answers `EINPROGRESS` at once, so the channel's lock is never held while a
    /// silent address times out; the caller waits for the socket to become writable, with its own timeout, then reads
    /// `SO_ERROR` (`oidc_net`).
    pub fn connect(&self, addr: SocketAddr) -> io::Result<OwnedFd> {
        let (sa, len) = sockaddr_bytes(&addr);
        // SAFETY: a plain syscall; the fd is owned by the `OwnedFd` below.
        let raw = unsafe {
            libc::socket(
                family_of(&addr),
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if raw < 0 {
            return Err(err("socket"));
        }
        // SAFETY: `raw` is a fresh fd, ours from here on.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let inner = self
            .inner
            .lock()
            .map_err(|_| io::Error::other("casper: lock poisoned"))?;
        // SAFETY: `net` is a valid channel, `fd` a live socket it accepts, `sa`/`len` a valid sockaddr. The
        // service connects the descriptor in place; it stays ours (no transfer, no second owner).
        let r = unsafe { cap_connect(inner.net, fd.as_raw_fd(), sa.as_ptr() as *const libc::sockaddr, len) };
        if r != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(err("cap_connect"));
        }
        Ok(fd)
    }
}

impl Drop for CasperNet {
    fn drop(&mut self) {
        if let Ok(inner) = self.inner.lock() {
            // SAFETY: the channels are ours, closed once.
            unsafe {
                cap_close(inner.net);
                cap_close(inner.chan);
            }
        }
    }
}

/// The C address family of a `SocketAddr`.
fn family_of(a: &SocketAddr) -> c_int {
    if a.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 }
}

/// A `SocketAddr` as the C `sockaddr` bytes the Casper service expects.
fn sockaddr_bytes(a: &SocketAddr) -> (Vec<u8>, u32) {
    match a {
        SocketAddr::V4(v4) => {
            let sa = libc::sockaddr_in {
                sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                sin_family: libc::AF_INET as u8,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(*v4.ip()).to_be(),
                },
                sin_zero: [0; 8],
            };
            let bytes = unsafe {
                std::slice::from_raw_parts(&sa as *const _ as *const u8, std::mem::size_of::<libc::sockaddr_in>())
            };
            (bytes.to_vec(), std::mem::size_of::<libc::sockaddr_in>() as u32)
        }
        SocketAddr::V6(v6) => {
            let sa = libc::sockaddr_in6 {
                sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                sin6_family: libc::AF_INET6 as u8,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            let bytes = unsafe {
                std::slice::from_raw_parts(&sa as *const _ as *const u8, std::mem::size_of::<libc::sockaddr_in6>())
            };
            (bytes.to_vec(), std::mem::size_of::<libc::sockaddr_in6>() as u32)
        }
    }
}

/// A C `sockaddr` back to a `SocketAddr`.
fn sockaddr_of(sa: &libc::sockaddr, len: libc::socklen_t) -> Option<SocketAddr> {
    match sa.sa_family as c_int {
        libc::AF_INET if len >= std::mem::size_of::<libc::sockaddr_in>() as u32 => {
            let sin = unsafe { &*(sa as *const _ as *const libc::sockaddr_in) };
            Some(SocketAddr::V4(SocketAddrV4::new(
                std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)),
                u16::from_be(sin.sin_port),
            )))
        }
        libc::AF_INET6 if len >= std::mem::size_of::<libc::sockaddr_in6>() as u32 => {
            let sin6 = unsafe { &*(sa as *const _ as *const libc::sockaddr_in6) };
            Some(SocketAddr::V6(SocketAddrV6::new(
                std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                u16::from_be(sin6.sin6_port),
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_round_trip() {
        for a in [
            SocketAddr::from((std::net::Ipv4Addr::new(192, 0, 2, 10), 443)),
            SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 8080)),
            "[2001:db8::1]:443".parse().unwrap(),
        ] {
            let (bytes, len) = sockaddr_bytes(&a);
            let sa = unsafe { &*(bytes.as_ptr() as *const libc::sockaddr) };
            assert_eq!(sockaddr_of(sa, len), Some(a), "{a}");
        }
    }

    #[test]
    fn sockaddr_of_refuses_garbage() {
        // Unknown family.
        let mut sa: libc::sockaddr = unsafe { std::mem::zeroed() };
        sa.sa_family = libc::AF_UNIX as _;
        assert_eq!(sockaddr_of(&sa, std::mem::size_of::<libc::sockaddr>() as u32), None);
        // Right family, truncated length (both families).
        for a in [
            SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 443)),
            "[2001:db8::1]:443".parse().unwrap(),
        ] {
            let (bytes, len) = sockaddr_bytes(&a);
            let sap = unsafe { &*(bytes.as_ptr() as *const libc::sockaddr) };
            assert_eq!(sockaddr_of(sap, len - 1), None, "{a}");
        }
        // Interior NUL is refused at the C string boundary.
        assert!(cstr("a\0b").is_err());
    }

    /// The service opens without any daemon (libcasper forks it), the allowlist holds: a declared name
    /// resolves, an undeclared one is refused, and a connection to a resolved address goes through.
    #[test]
    fn service_opens_and_enforces_the_allowlist() {
        if crate::fs::forked_elsewhere("fs::casper::tests::service_opens_and_enforces_the_allowlist") {
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let net = CasperNet::open(&[("localhost".to_string(), port)], &[]).unwrap();
        let addrs = net.resolve("localhost", port).unwrap();
        assert!(
            addrs.contains(&SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port))),
            "{addrs:?}"
        );
        // A name that is not in the allowlist is refused by the service.
        assert!(net.resolve("example.invalid", port).is_err());
        // Connect through the channel: the service starts the connection (non-blocking socket), we talk on it once
        // the listener has accepted it.
        let fd = net
            .connect(SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)))
            .unwrap();
        use std::io::{Read as _, Write as _};
        let mut stream: std::net::TcpStream = fd.into();
        let (mut s, _) = listener.accept().unwrap();
        stream.set_nonblocking(false).unwrap();
        stream.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        // A destination that is not on the allowlist: the service refuses, never a silent fallback.
        let other = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let refused = net.connect(other.local_addr().unwrap());
        assert!(refused.is_err(), "an undeclared address was connected");
    }
}
