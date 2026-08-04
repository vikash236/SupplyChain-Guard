// Safe, standard Rust build script
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src/native.c");
    println!("cargo:rustc-link-lib=static=native");
}
