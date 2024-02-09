#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

fn harness(data: &[u8]) {
    // Wrap it in an `Unstructured`.
    let mut unstructured = Unstructured::new(data);

    // Generate an `Name` and run our checks.
    if let Ok(name) = project::Name::arbitrary(&mut unstructured) {
        name.check_buf();
    }
}

fuzz_target!(|data: &[u8]| {
    harness(data);
});
