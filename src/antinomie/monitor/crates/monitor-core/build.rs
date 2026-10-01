fn main() {
    let transport = "../../../transport";
    cc::Build::new()
        .file(format!("{transport}/host.c"))
        .file("src/ffi_layout.c")
        .include(transport)
        .flag("-std=gnu11")
        .compile("ant_host");
    println!("cargo:rerun-if-changed={transport}");
    println!("cargo:rerun-if-changed=src/ffi_layout.c");
}
