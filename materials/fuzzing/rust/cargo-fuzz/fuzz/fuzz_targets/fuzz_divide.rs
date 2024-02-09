#![no_main]

use libfuzzer_sys::fuzz_target;
use std::slice;

fuzz_target!(|data: &[u8]| {
    let size = data.len();
    if size != 2 * std::mem::size_of::<i32>() {
        return;
    }

    // Split input into numerator and denominator
    let numerator = i32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    let denominator = i32::from_ne_bytes([data[4], data[5], data[6], data[7]]);

    project::divide(numerator, denominator);
});
