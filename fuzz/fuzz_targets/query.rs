#![no_main]
// Arbitrary text of the web search (`/web/search?q=`): operators, folding, highlighting.
libfuzzer_sys::fuzz_target!(|data: &[u8]| beastbox::index::fuzz_query(data));
