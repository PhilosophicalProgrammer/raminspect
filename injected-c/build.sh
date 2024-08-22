#!/bin/bash
gcc -Isrc/musl-syscalls/"$(uname -m)" -c src/allocmem.c -ffreestanding -nostdlib -O3 -o build/allocmem.o
ld -Tsrc/allocmem.ld build/allocmem.o -o build/allocmem.bin
gcc -c src/forever.c -ffreestanding -nostdlib -O3 -o build/forever.o
ld -Tsrc/forever.ld build/forever.o -o build/forever.bin