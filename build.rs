use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=injected-c/src/allocmem.c");
    println!("cargo:rerun-if-changed=injected-c/src/forever.c");

    // Invoke `build.sh`.
    Command::new("bash").arg("-c").arg("cd injected-c && bash build.sh").output().expect("Failed to run build.sh");
}