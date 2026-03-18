#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static CHECK_BUF: OnceLock<project::CheckBufSlowInit> = OnceLock::new();

fuzz_target!(
    init: {
        CHECK_BUF.set(project::CheckBufSlowInit::new()).unwrap();
    },
    |data: &[u8]| {
        let check_buf = CHECK_BUF.get().unwrap();
        check_buf.check(data);
    }
);
