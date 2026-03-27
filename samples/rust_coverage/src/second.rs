use crate::Data;

pub(crate) fn validate_data_panic(data: &Data) {
    if data.len == 0 {
        panic!("panic")
    }
}