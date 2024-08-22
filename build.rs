use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=injected-c/src/allocmem.c");
    println!("cargo:rerun-if-changed=injected-c/src/forever.c");

    // Invoke `build.sh`.
    let output = Command::new("sh").arg("-c").arg("cd injected-c && sh build.sh").output().expect("Failed to run build.sh");

    if !output.status.success() {
        panic!("Build script failed with stderr: {}", String::from_utf8_lossy(&output.stderr));
    }
}