#![no_main]
// Arbitrary source trees (snapshot or restored backup: names chosen by users): `restore` never crashes, never touches
// the existing items nor writes outside its target, and copies faithfully.
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let (src, live) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    beastbox::dav::fuzz::restore(data, src.path(), live.path());
});
