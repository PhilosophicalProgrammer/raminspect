//! This module contains register set definitions for all of the supported architectures of `raminspect`.
//! This is necessary to write out manually because kernel structure definitions are not exposed to
//! userspace. All contained definitions are directly copied from the kernel source code and
//! translated to Rust.

#![allow(non_camel_case_types)]
use nix::libc::*;

#[cfg(target_arch = "x86_64")]
#[repr(C)]

pub struct pt_regs {
	pub r15: c_ulong,
	pub r14: c_ulong,
	pub r13: c_ulong,
	pub r12: c_ulong,
	pub rbp: c_ulong,
	pub rbx: c_ulong,
	pub r11: c_ulong,
	pub r10: c_ulong,
	pub r9: c_ulong,
	pub r8: c_ulong,
	pub rax: c_ulong,
	pub rcx: c_ulong,
	pub rdx: c_ulong,
	pub rsi: c_ulong,
	pub rdi: c_ulong,
	pub rip: c_ulong,
	pub cs: c_ulong,
	pub eflags: c_ulong,
	pub rsp: c_ulong,
	pub ss: c_ulong,
}

#[cfg(target_arch = "x86")]
#[repr(C)]

pub struct pt_regs {
    pub ebx: c_long,
	pub ecx: c_long,
	pub edx: c_long,
	pub esi: c_long,
	pub edi: c_long,
	pub ebp: c_long,
	pub eax: c_long,
	pub xds: c_int,
	pub xes: c_int,
	pub xfs: c_int,
	pub xgs: c_int,
	pub orig_eax: c_long,
	pub eip: c_long,
	pub xcs: c_int,
	pub eflags: c_long,
	pub esp: c_long,
	pub xss: c_int,
}

#[cfg(target_arch = "arm")]

struct pt_regs {
    pub uregs: [c_ulong; 18]
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]

struct pt_regs {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
    pub orig_x0: u64,
    pub syscallno: u64,
    pub sdei_ttrb1: u64,
    pub pmr_save: u64,
    pub stackframe: [u64; 2],
    pub lockdep_hardirqs: u64,
    pub exit_rcu: u64,
}

#[cfg(target_arch = "csky")]
#[repr(C)]

struct pt_regs {
    pub tls: c_ulong,
	pub lr: c_ulong,
	pub pc: c_ulong,
	pub sr: c_ulong,
	pub usp: c_ulong,
	pub orig_a0: c_ulong,
	pub a0: c_ulong,
	pub a1: c_ulong,
	pub a2: c_ulong,
	pub a3: c_ulong,

    // We only support `csky` ABI version 2.
	pub regs: [c_ulong; 10],
    pub exregs: [c_ulong; 15],

	pub rhi: c_ulong,
	pub rlo: c_ulong,
	pub dcsr: c_ulong,
}

#[cfg(any(target_arch = "riscv64", target_arch = "riscv32"))]
#[repr(C)]

struct pt_regs {
	pub epc: c_ulong,
	pub ra: c_ulong,
	pub sp: c_ulong,
	pub gp: c_ulong,
	pub tp: c_ulong,
	pub t0: c_ulong,
	pub t1: c_ulong,
	pub t2: c_ulong,
	pub s0: c_ulong,
	pub s1: c_ulong,
	pub a0: c_ulong,
	pub a1: c_ulong,
	pub a2: c_ulong,
	pub a3: c_ulong,
	pub a4: c_ulong,
	pub a5: c_ulong,
	pub a6: c_ulong,
	pub a7: c_ulong,
	pub s2: c_ulong,
	pub s3: c_ulong,
	pub s4: c_ulong,
	pub s5: c_ulong,
	pub s6: c_ulong,
	pub s7: c_ulong,
	pub s8: c_ulong,
	pub s9: c_ulong,
	pub s10: c_ulong,
	pub s11: c_ulong,
	pub t3: c_ulong,
	pub t4: c_ulong,
	pub t5: c_ulong,
	pub t6: c_ulong,
	pub status: c_ulong,
	pub badaddr: c_ulong,
	pub cause: c_ulong,
	pub orig_a0: c_ulong,
}

#[cfg(target_arch = "sparc")]
#[repr(C)]

struct pt_regs {
    pub psr: c_ulong,
	pub pc: c_ulong,
	pub npc: c_ulong,
	pub y: c_ulong,
	pub uregs: [c_ulong; 16],
}

#[cfg(target_arch = "sparc64")]
#[repr(C)]

struct pt_regs {
	pub uregs: [c_ulong; 16],
	pub tstate: c_ulong,
	pub tpc: c_ulong,
	pub tnpc: c_ulong,
    pub y: c_uint,
    pub magic: c_uint,
}

#[cfg(any(target_arch = "mips64", target_arch = "mips64r6"))]
#[repr(C, align(8))]

struct pt_regs {
    pub regs: [c_ulong; 32],
	pub cp0_status: c_ulong,
	pub hi: c_ulong,
	pub lo: c_ulong,
	pub cp0_badvaddr: c_ulong,
	pub cp0_cause: c_ulong,
	pub cp0_epc: c_ulong,
    pub __last: [c_ulong; 0],
}

#[cfg(any(target_arch = "mips", target_arch = "mips32r6"))]
#[repr(C, align(8))]

struct pt_regs {
    pub pad0: [c_ulong; 8],
    pub regs: [c_ulong; 32],
	pub cp0_status: c_ulong,
	pub hi: c_ulong,
	pub lo: c_ulong,
	pub cp0_badvaddr: c_ulong,
	pub cp0_cause: c_ulong,
	pub cp0_epc: c_ulong,
    pub __last: [c_ulong; 0],
}

impl pt_regs {
    pub fn inst_ptr(&mut self) -> &mut c_ulong {
        #[cfg(target_arch = "x86_64")]
        return &mut self.rip;

        #[cfg(target_arch = "x86")]
        return &mut self.eip;

        #[cfg(target_arch = "arm")]
        return &mut self.uregs[15];

        #[cfg(target_arch = "aarch64")]
        return &mut self.pc;

        #[cfg(target_arch = "csky")]
        return &mut self.pc;

        #[cfg(any(target_arch = "riscv64", target_arch = "riscv32"))]
        return &mut self.epc;

        #[cfg(target_arch = "sparc")]
        return &mut self.pc;

        #[cfg(target_arch = "sparc64")]
        return &mut self.tpc;

        #[cfg(any(target_arch = "mips", target_arch = "mips32r6", target_arch = "mips64", target_arch = "mips64r6"))]
        return &mut self.cp0_epc;
    }

    pub fn stack_ptr(&mut self) -> &mut c_ulong {
        #[cfg(target_arch = "x86_64")]
        return &mut self.rsp;

        #[cfg(target_arch = "x86")]
        return &mut self.esp;

        #[cfg(target_arch = "arm")]
        return &mut self.uregs[13];

        #[cfg(target_arch = "aarch64")]
        return &mut self.sp;

        #[cfg(target_arch = "csky")]
        return &mut self.usp;

        #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
        return &mut self.sp;

        #[cfg(any(target_arch = "sparc", target_arch = "sparc64"))]
        return &mut self.uregs[14];

        #[cfg(any(target_arch = "mips", target_arch = "mips32r6", target_arch = "mips64", target_arch = "mips64r6"))]
        return &mut self.regs[29];
    }
}

// We refuse to compile if the user is using an unsupported CPU architecture.

#[cfg(not(any(
    target_arch = "riscv32", target_arch = "riscv64",
    target_arch = "sparc", target_arch = "sparc64",
    target_arch = "mips64", target_arch = "mips64r6",
    target_arch = "mips", target_arch = "mips32r6",
    target_arch = "x86", target_arch = "x86_64",
    target_arch = "arm", target_arch = "aarch64",
    target_arch = "csky",
)))]

compile_error!("You're using an unsupported CPU architecture. If you believe that it should be supported, open a GitHub issue.");