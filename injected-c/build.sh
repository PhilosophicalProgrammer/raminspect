#!/bin/sh
function fail {
    echo $1 1>&2
    exit 1
}

# Check if gcc and ld are installed
command -v gcc >/dev/null 2>&1 || fail "gcc could not be found."
command -v ld >/dev/null 2>&1 || fail "ld could not be found."

# Target detection copied from MUSL configure file
TARGET=$(gcc -dumpmachine 2>/dev/null)

case "$TARGET" in
    arm*) ARCH=arm ;;
    aarch64*) ARCH=aarch64 ;;
    i?86-nt32*) ARCH=nt32 ;;
    i?86*) ARCH=i386 ;;
    x86_64-x32*|x32*|x86_64*x32) ARCH=x32 ;;
    x86_64-nt64*) ARCH=nt64 ;;
    x86_64*) ARCH=x86_64 ;;
    loongarch64*) ARCH=loongarch64 ;;
    m68k*) ARCH=m68k ;;
    mips64*|mipsisa64*) ARCH=mips64 ;;
    mips*) ARCH=mips ;;
    microblaze*) ARCH=microblaze ;;
    or1k*) ARCH=or1k ;;
    powerpc64*|ppc64*) ARCH=powerpc64 ;;
    powerpc*|ppc*) ARCH=powerpc ;;
    riscv64*) ARCH=riscv64 ;;
    riscv32*) ARCH=riscv32 ;;
    sh[1-9bel-]*|sh|superh*) ARCH=sh ;;
    s390x*) ARCH=s390x ;;
    unknown) fail "Unable to detect target architecture." ;;
    *) fail "Unknown or unsupported target: $TARGET" ;;
esac

gcc -Isrc/musl-syscalls/$ARCH -c src/allocmem.c -ffreestanding -nostdlib -O3 -o build/allocmem.o &&
ld -Tsrc/allocmem.ld build/allocmem.o -o build/allocmem.bin &&
gcc -c src/forever.c -ffreestanding -nostdlib -O3 -o build/forever.o &&
ld -Tsrc/forever.ld build/forever.o -o build/forever.bin