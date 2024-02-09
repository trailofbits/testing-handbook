#![no_main]

use libfuzzer_sys::fuzz_target;

fn harness(data: &[u8]) {
    project::check_buf(data);
}

fuzz_target!(|data: &[u8]| {
    harness(data);
});
