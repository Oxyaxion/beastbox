#![no_main]
// Arbitrary paths and header values: SafePath, Destination, Range, If-Match, OC-Checksum, X-OC-Mtime, Host.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        beastbox::dav::fuzz::headers(s);
    }
});
