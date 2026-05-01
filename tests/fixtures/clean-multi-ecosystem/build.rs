fn main() {
    // Pure declarative: rerun whenever wrapper.h changes. No network, no Command.
    println!("cargo:rerun-if-changed=wrapper.h");
}
