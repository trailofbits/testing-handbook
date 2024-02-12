#![no_main]

use libfuzzer_sys::fuzz_target;

fn harness(data: &project::Name) {
    data.check_buf();
}

fuzz_target!(|data: project::Name| {
    harness(&data);
});
