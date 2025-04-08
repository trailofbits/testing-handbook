#![cfg_attr(not(any(miri, test)), no_main)]

use libfuzzer_sys::fuzz_target;
use rust_tests::check_buf;
fn harness(data: &[u8]) {
    check_buf(data);
}

fuzz_target!(|data: &[u8]| {
    harness(data);
});

#[cfg(test)]
#[cfg(miri)]
mod tests {
    use {
        crate::{harness},
        rstest::rstest,
        std::{fs::File, io::Read, path::PathBuf},
    };

    #[rstest]
    fn miri(#[files("corpus/fuzz_target_1/*")] path: PathBuf) {
        let mut input = File::open(path).unwrap();
        let mut buf = Vec::new();
        input.read_to_end(&mut buf).unwrap();
        harness(&buf);
    }
}