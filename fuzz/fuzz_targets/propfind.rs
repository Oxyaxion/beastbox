#![no_main]
// Arbitrary PROPFIND bodies (risk area §0.3: quick-xml).
libfuzzer_sys::fuzz_target!(|data: &[u8]| beastbox::dav::fuzz::propfind(data));
