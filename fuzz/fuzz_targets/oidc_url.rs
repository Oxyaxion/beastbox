#![no_main]
// Arbitrary text as an `https` URL (issuer, discovery endpoints, `backchannel_hosts`).
libfuzzer_sys::fuzz_target!(|data: &[u8]| beastbox::auth::oidc::fuzz_url(data));
