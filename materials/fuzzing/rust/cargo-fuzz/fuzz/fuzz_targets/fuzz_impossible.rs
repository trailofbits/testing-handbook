#![no_main]

use libfuzzer_sys::fuzz_target;
use std::process;
use std::slice;

fuzz_target!(|data: &[u8]| {
    if let Ok(string) = String::from_utf8(data.to_vec()) {
        if string.len() > 100 {
            if string.len() > 200 {
                if string.len() > 300 {
                    if string.len() > 400 {
                        if string.len() > 500 {
                            process::abort();
                        }
                    }
                }
            }
        }
    }
});
