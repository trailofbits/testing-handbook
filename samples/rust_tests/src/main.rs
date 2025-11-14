#![feature(custom_inner_attributes, proc_macro_hygiene)]

use rust_tests::check_buf;

mod unit_tests;

fn main() {
    println!("Hello, world!");
    let buffer: &[u8] = b"123";
    check_buf(buffer);
}

/* Unit Testing */
static mut GLOB_VAR: i32 = 2;

unsafe fn global_var_set(arg: i32) {
    GLOB_VAR = arg;
}

#[allow(unreachable_code)]
fn feature_one() -> i32 {
    #[cfg(all(feature = "fone", feature = "fthree", not(feature = "ftwo")))]
    {
        return 3;
    }
    #[cfg(feature = "fone")] {
        return 1;
    }
    #[cfg(feature = "ftwo")] {
        return 2;
    }
    return 0;
}

mod overflow_lib {
    // #![cast_checks::enable]

    pub(crate) fn do_overflow(a: i32) -> i32 {
        return a * 8;
    }

    pub(crate) fn as_u16(z: i32) -> u16 {
        z as u16
    }
}

fn simple_thingy_dingy(a: u64, b: &str) -> u64 {
    return a + match b.parse::<u64>() {
        Ok(x) => x,
        Err(_) => b.len() as u64,
    };
}

fn validate_data(data: &Data) -> Result<(), ()> {
    if !data.magic.eq(&[0x13, 0x37]) { return Err(()) }
    if data.len as usize != data.content.len() { return Err(()) }
    return Ok(());
}

struct Data {
    magic: [u8; 2],
    len: u8,
    content: String
}

/* END Unit Testing */


