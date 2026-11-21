#![no_main]
// Arbitrary PROPPATCH bodies (risk area §0.3: quick-xml; names echoed in the response).
libfuzzer_sys::fuzz_target!(|data: &[u8]| beastbox::dav::fuzz::proppatch(data));
