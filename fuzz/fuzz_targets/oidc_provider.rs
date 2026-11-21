#![no_main]
// Arbitrary bytes as a provider response: discovery document, token response, `id_token` payload.
libfuzzer_sys::fuzz_target!(|data: &[u8]| beastbox::auth::oidc::fuzz_provider(data));
