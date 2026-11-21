#![no_main]
// Arbitrary manifests (file back from external storage): never a crash, entries reread identically.
libfuzzer_sys::fuzz_target!(|data: &[u8]| beastbox::dav::fuzz::manifest(data));
