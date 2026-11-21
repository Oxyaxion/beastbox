#![no_main]
// Arbitrary file for `core/preview`: the JPEG decoder and our code (orientation, shrink, rotation) never crash, and a
// result is always a readable JPEG no bigger than asked.
libfuzzer_sys::fuzz_target!(|data: &[u8]| beastbox::nc::thumb::fuzz(data));
