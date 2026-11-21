#![no_main]
// Arbitrary SEARCH bodies (risk area §0.3: quick-xml, clients' WebDAV search).
libfuzzer_sys::fuzz_target!(|data: &[u8]| beastbox::dav::fuzz::search(data));
