mod second;

fn main() { println!("Hello, world!"); }

fn validate_data_simple(data: &Data) -> Result<(), ()> {
    if !data.magic.eq(&[0x13, 0x37]) { return Err(()) }
    if data.len as usize != data.content.len() { return Err(()) }
    return Ok(());
}

fn validate_data_match(data: &Data) -> i32 {
    let x: u32 = match data.content.parse::<u32>() {
        Ok(_x) => {
            let y = 2 * _x;
            if y < 6 {
                y
            } else {
                y * 2
            }
        }
        Err(_) => 0
    };
    if x == 0 {
        -1
    } else {
        (x as i32) + 1
    }
}

// https://doc.rust-lang.org/book/ch10-01-syntax.html
fn largest<T: PartialOrd>(list: &[T]) -> &T {
    let mut largest = &list[0];
    for item in list {
        if item > largest {
            largest = item;
        }
    }
    largest
}

fn validate_data_generics(data: &Data) {
    let number_list = vec![34, 50, 25, 100, 65];

    let result = largest(&number_list);
    println!("The largest number is {}", result);

    let char_list = vec!['y', 'm', 'a', 'q'];

    let result = largest(&char_list);
    println!("The largest char is {}", result);

    let result = largest(data.content.as_bytes());
    println!("The largest content char is {}", result);
}

struct Data {
    magic: [u8; 2],
    len: u8,
    content: String
}

#[cfg(test)]
mod tests {
    use crate::second::validate_data_panic;
    use crate::{Data, validate_data_generics, validate_data_match, validate_data_simple};

    #[test]
    fn parser_detects_errors() {
        let mut blob = Data{ magic: [0x73, 0x31], len: 2, content: "AB".parse().unwrap() };
        blob.content = blob.content + "Y";
        let result = validate_data_simple(&blob);
        assert!(result.is_err());
    }

    #[test]
    fn check_match() {
        let blob = Data{ magic: [0x73, 0x31], len: 2, content: "XX".parse().unwrap() };
        let x = validate_data_match(&blob);
        assert_eq!(x, -1);
    }

    #[test]
    fn check_match2() {
        let blob = Data{ magic: [0x73, 0x31], len: 2, content: "40".parse().unwrap() };
        let x = validate_data_match(&blob);
        assert_eq!(x, 161);
    }

    #[test]
    fn check_generic() {
        let blob = Data{ magic: [0x73, 0x31], len: 2, content: "QWE".parse().unwrap() };
        validate_data_generics(&blob);
    }

    #[test]
    #[should_panic]
    fn check_panic() {
        let blob = Data{ magic: [0x73, 0x31], len: 0, content: "4".parse().unwrap() };
        validate_data_panic(&blob);
    }

    #[test]
    fn check_not_panic() {
        let blob = Data{ magic: [0x73, 0x31], len: 2, content: "4".parse().unwrap() };
        validate_data_panic(&blob);
    }
}