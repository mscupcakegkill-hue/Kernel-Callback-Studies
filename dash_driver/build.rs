fn main() {
    // Driver link options — emitted only for THIS crate's final binary,
    // so dependency build scripts (which need the CRT) are unaffected.
    println!("cargo:rustc-link-arg=/ENTRY:DriverEntry");
    println!("cargo:rustc-link-arg=/SUBSYSTEM:NATIVE");
    println!("cargo:rustc-link-arg=/DRIVER");
    println!("cargo:rustc-link-arg=/NODEFAULTLIB");
    println!("cargo:rustc-link-arg=/MANIFEST:NO");
}
