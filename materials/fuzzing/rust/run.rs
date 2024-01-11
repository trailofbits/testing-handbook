/// Link to the C function LLVMFuzzerTestOneInput
extern {
    fn LLVMFuzzerTestOneInput(Data: *const u8, Size: size_t);
}

fn main() {
    // Get the first argument
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Please provide a directory as an argument");
        return;
    }
    
    let dir = &args[1];
    
    let paths = fs::read_dir(dir).unwrap();

    for path in paths {
        let path = path.unwrap().path();
        if path.is_file() {
            let mut file = fs::File::open(&path).unwrap();
            let mut contents = Vec::new();
            file.read_to_end(&mut contents).unwrap();

            // call LLVMFuzzerTestOneInput for each file
            let c_data = CString::new(contents).unwrap();
            unsafe {
                LLVMFuzzerTestOneInput(c_data.as_ptr() as *const u8, c_data.as_bytes().len());
            }
        }
    }
}
