#![no_main]
// Arbitrary requests on the real router (method, route, headers, body): no panic, never a 500, nothing written
// outside the data roots. Built for the drop links hardening (0.9); covers WebDAV, uploads, links, previews, web.
// The bench (tenants, users, links) is built once and kept here: the server itself has no global state (§4.1).
static BENCH: std::sync::OnceLock<beastbox::http::fuzz::Bench> = std::sync::OnceLock::new();
libfuzzer_sys::fuzz_target!(|data: &[u8]| beastbox::http::fuzz::request(BENCH.get_or_init(Default::default), data));
