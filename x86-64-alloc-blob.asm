; This is an architecture-specific routine that allocates memory in the process that it is injected into.
; It made to be completely position-independent since it could be loaded anywhere, hence why this is
; written in raw assembly and not C. Contributions that port this to platforms other than x86-64 are
; welcome.

[BITS 64]
; Define constants used in system calls

NULL equ 0x00
O_RDONLY equ 0x00
SYS_READ equ 0x00
SYS_OPEN equ 0x02
SYS_MMAP equ 0x09
SYS_CLOSE equ 0x03
PROT_READ equ 0x01
PROT_EXEC equ 0x04
PROT_WRITE equ 0x02
MAP_SHARED equ 0x01
MAP_ANONYMOUS equ 0x20

; Allocate memory based on `alloc_size`, which is set to an appropriate value by the `raminspect`
; framework before this is loaded.

mov rax, SYS_MMAP
mov rdi, NULL
mov rsi, [rel $ + (alloc_size - $)]
mov rdx, PROT_READ | PROT_WRITE | PROT_EXEC
mov r10, MAP_ANONYMOUS | MAP_SHARED
mov r8, -1
mov r9, 0
syscall

; Store the output pointer for use by the framework. Note that we aren't
; handling errors here because the error handling is deferred to
; the higher-level parts of `raminspect`.
mov [rel $ + (out_ptr - $)], rax

; Open the raminspect device file

mov rax, SYS_OPEN
lea rdi, [rel $ + (devpath - $)]
mov rsi, O_RDONLY
mov rdx, NULL
syscall

; Read exactly one byte from it as a signal. We specify the output buffer
; as NULL, since we aren't actually reading any data.

mov rdi, rax
mov rax, SYS_READ
mov rsi, NULL
mov rdx, 1
syscall

; Close the device file
mov rax, SYS_CLOSE
syscall

; Pause program execution until `raminspect` acknowledges the signal and detects that
; we're done, at which point it'll restore the old program instructions and this will
; stop executing.
jmp $

; The path to the `raminspect` device file, fixed to `/dev/raminspect`
devpath: db "/dev/raminspect", 0

; The output of the assembly routine. This is read by `raminspect` after this finishes
; executing. The error handling logic determines whether or not there was an error
; by checking if this is still set to null after the routine finishes.
out_ptr: dq 0

; The size of the memory allocation, set to an appropriate value by raminspect before
; the routine is injected into the process.
alloc_size: dq 0
