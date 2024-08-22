//! This module contains register set definitions for all of the supported architectures of `raminspect`.
//! This is necessary to write out manually because kernel structure definitions are not exposed to
//! userspace. All contained definitions are directly copied from the kernel source code and
//! translated to Rust.

#![allow(non_camel_case_types)]
use nix::libc::*;

#[doc(hidden)]
// Used internally to define register structures.

macro_rules! defineregs {
	($($arch:literal)&&*$(, $align:literal)? {
		$($regname:ident: $regty:ty),*$(,)?
	}) => {
		#[cfg(any($(target_arch = $arch),*))]
		#[repr(C$(, align($align))?)]
		#[derive(Clone, Debug)]

		/// The registers structure for your target architecture. Note that these are general-purpose registers:
		/// floating-point registers are not included for performance and cross-platform compatibility reasons.
		/// It corresponds directly with the `pt_regs` struct defined in the Linux kernel source code.

		pub struct pt_regs {
			$(
				#[doc = concat!(stringify!($regname), " register.")]
				pub $regname: $regty,
			)*
		}
	}
}

defineregs!("x86_64" {
	r15: c_ulong,
	r14: c_ulong,
	r13: c_ulong,
	r12: c_ulong,
	bp: c_ulong,
	bx: c_ulong,
	r11: c_ulong,
	r10: c_ulong,
	r9: c_ulong,
	r8: c_ulong,
	ax: c_ulong,
	cx: c_ulong,
	dx: c_ulong,
	si: c_ulong,
	di: c_ulong,
	orig_ax: c_ulong,
	ip: c_ulong,
	csx: c_ulong,
	flags: c_ulong,
	sp: c_ulong,
	ssx: c_ulong,
});

defineregs!("x86" {
    ebx: c_long,
	ecx: c_long,
	edx: c_long,
	esi: c_long,
	edi: c_long,
	ebp: c_long,
	eax: c_long,
	xds: c_int,
	xes: c_int,
	xfs: c_int,
	xgs: c_int,
	orig_eax: c_long,
	eip: c_long,
	xcs: c_int,
	eflags: c_long,
	esp: c_long,
	xss: c_int,
});

defineregs!("arm" {
    uregs: [c_ulong; 18]
});

defineregs!("aarch64" {
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
    orig_x0: u64,
    syscallno: u64,
    sdei_ttrb1: u64,
    pmr_save: u64,
    stackframe: [u64; 2],
    lockdep_hardirqs: u64,
    exit_rcu: u64,
});

defineregs!("csky" {
    tls: c_ulong,
	lr: c_ulong,
	pc: c_ulong,
	sr: c_ulong,
	usp: c_ulong,
	orig_a0: c_ulong,
	a0: c_ulong,
	a1: c_ulong,
	a2: c_ulong,
	a3: c_ulong,

    // We only support `csky` ABI version 2.
	regs: [c_ulong; 10],
    exregs: [c_ulong; 15],

	rhi: c_ulong,
	rlo: c_ulong,
	dcsr: c_ulong,
});

defineregs!("riscv64" && "riscv32" {
	epc: c_ulong,
	ra: c_ulong,
	sp: c_ulong,
	gp: c_ulong,
	tp: c_ulong,
	t0: c_ulong,
	t1: c_ulong,
	t2: c_ulong,
	s0: c_ulong,
	s1: c_ulong,
	a0: c_ulong,
	a1: c_ulong,
	a2: c_ulong,
	a3: c_ulong,
	a4: c_ulong,
	a5: c_ulong,
	a6: c_ulong,
	a7: c_ulong,
	s2: c_ulong,
	s3: c_ulong,
	s4: c_ulong,
	s5: c_ulong,
	s6: c_ulong,
	s7: c_ulong,
	s8: c_ulong,
	s9: c_ulong,
	s10: c_ulong,
	s11: c_ulong,
	t3: c_ulong,
	t4: c_ulong,
	t5: c_ulong,
	t6: c_ulong,
	status: c_ulong,
	badaddr: c_ulong,
	cause: c_ulong,
	orig_a0: c_ulong,
});

defineregs!("sparc" {
    psr: c_ulong,
	pc: c_ulong,
	npc: c_ulong,
	y: c_ulong,
	uregs: [c_ulong; 16],
});

defineregs!("sparc64" {
	uregs: [c_ulong; 16],
	tstate: c_ulong,
	tpc: c_ulong,
	tnpc: c_ulong,
    y: c_uint,
    magic: c_uint,
});

defineregs!("mips64" && "mips64r6", 8 {
    regs: [c_ulong; 32],
	cp0_status: c_ulong,
	hi: c_ulong,
	lo: c_ulong,
	cp0_badvaddr: c_ulong,
	cp0_cause: c_ulong,
	cp0_epc: c_ulong,
    __last: [c_ulong; 0],
});

defineregs!("mips" && "mips32r6", 8 {
    pad0: [c_ulong; 8],
    regs: [c_ulong; 32],
	cp0_status: c_ulong,
	hi: c_ulong,
	lo: c_ulong,
	cp0_badvaddr: c_ulong,
	cp0_cause: c_ulong,
	cp0_epc: c_ulong,
    __last: [c_ulong; 0],
});

impl pt_regs {
	/// Gets the instruction pointer.
    pub fn inst_ptr(&mut self) -> &mut c_ulong {
        #[cfg(target_arch = "x86_64")]
        return &mut self.ip;

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

	/// Gets the stack pointer.
    pub fn stack_ptr(&mut self) -> &mut c_ulong {
        #[cfg(target_arch = "x86_64")]
        return &mut self.sp;

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