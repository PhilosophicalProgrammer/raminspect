// This is compiled and linked as a raw binary in `build.rs`, and the bytes of the resulting binary are retrieved via
// `include_bytes` in the library and used in the `allocate_memory` function of `RamInspector`. In other words, this
// is the custom shellcode that `raminspect` uses to allocate memory in a process.

// Include the system call functions for the relevant architecture. These files were extracted directly from the MUSL
// source code, which is directly included since we can't rely on the libc-provided `syscall` wrapper, and so we have
// to resort to lower-level internal definitions instead. This is because it requires `errno` (and, by extension,
// thread-local storage) to be available, which will not be the case when we're injected.
#include <syscall_arch.h>

// Only type definitions from these headers are used. For the reasons stated above, we can't use library functions.
#include <sys/syscall.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdint.h>
#include <unistd.h>

// The size of the requested allocation will be stored by the injector in this cookie.
volatile uint64_t SIZE_COOKIE = 0xF0CCF6B495854508;

// The address of the allocation will be stored in this cookie when we're done, for the injector to read. If an error
// occurs, the error code will be stored in it instead.
volatile uint64_t ADDR_COOKIE = 0xBFB04CDC2D0AB7B8;

// The process ID of the injector will be stored in this cookie. Used for sending it a signal when we're done.
volatile uint64_t PID_COOKIE = 0xBE05253FF57ECE7F;

__attribute__((naked)) void allocmem() {
    // Allocate the memory and then send a signal to the injector.
    ADDR_COOKIE = __syscall6(SYS_mmap, 0, SIZE_COOKIE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_SHARED, 0, 0);
    __syscall2(SYS_kill, PID_COOKIE, SIGUSR1);
    while(1) {}
}