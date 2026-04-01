fn main() {
    cc::Build::new()
        .cpp(true)
        .file("src/native/snek_native_opt.cpp")
        .compile("snek_native_opt");
    
    println!("cargo:rerun-if-changed=src/native/snek_native_opt.cpp");
}
