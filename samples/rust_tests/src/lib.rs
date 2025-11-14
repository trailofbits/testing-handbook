use std::process;

pub fn check_buf(buf: &[u8]) {
    if buf.len() > 0 && buf[0] == b'a' {
        if buf.len() > 1 && buf[1] == b'b' {
            if buf.len() > 2 && buf[2] == b'c' {
                process::abort();
            }
        }
    }
}