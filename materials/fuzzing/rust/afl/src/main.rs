
fn main_unused() {
    let buffer: &[u8] = b"123";
    project::check_buf(buffer);
}

// --

#[macro_use]
extern crate afl;

fn harness(data: &[u8]) {
    //project::check_buf(data);
    use std::process;
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
}


fn main() {
    fuzz!(|data: &[u8]| {
        harness(data);
    });
}
