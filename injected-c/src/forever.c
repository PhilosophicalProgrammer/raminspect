// This is compiled as a raw binary via `build.rs`, included via `include_bytes`, and then used in `execute_shellcode` in
// `RamInspector` as a way to pause the threads other than `main` while the shellcode is executing. In other words, this
// code is injected into threads by `raminspect` to make them spin-wait for the duration of modification.

__attribute__((naked)) void forever() {
    while(1) {}
}