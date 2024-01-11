#![no_main]
use libfuzzer_sys::fuzz_target;

pub trait Arithmetic: Sized {
    fn add(self, other: Self) -> Self;
    fn subtract(self, other: Self) -> Self;
    fn multiply(self, other: Self) -> Self;
    fn divide(self, other: Self) -> Option<Self>;
}

impl Arithmetic for f64 {
    fn add(self, other: Self) -> Self {
        self + other
    }

    fn subtract(self, other: Self) -> Self {
        self - other
    }

    fn multiply(self, other: Self) -> Self {
        self * other
    }

    fn divide(self, other: Self) -> Option<Self> {
        if other == 0.0 { None } else { Some(self / other) }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 1 + 2 * std::mem::size_of::<f64>() {
        return;  // Not enough data for mode and two f64 numbers
    }

    let mode = data[0];
    let numbers = &data[1..];

    if let [first, second] = *bytemuck::try_cast_slice::<_, f64>(numbers).unwrap_or_else(|_| &[0.0, 0.0]) {
        match mode % 4 {
            0 => { first.add(second); },
            1 => { first.subtract(second); },
            2 => { first.multiply(second); },
            3 => { first.divide(second); },
            _ => {}
        }
    }
});
