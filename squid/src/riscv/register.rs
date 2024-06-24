//! Contains everything related to RISC-V registers

#![allow(non_upper_case_globals)]

mod gp {
    pub(super) const zero: usize = 0;
    pub(super) const ra: usize = 1;
    pub(super) const sp: usize = 2;
    pub(super) const gp: usize = 3;
    pub(super) const tp: usize = 4;
    pub(super) const t0: usize = 5;
    pub(super) const t1: usize = 6;
    pub(super) const t2: usize = 7;
    pub(super) const s0: usize = 8;
    pub(super) const s1: usize = 9;
    pub(super) const a0: usize = 10;
    pub(super) const a1: usize = 11;
    pub(super) const a2: usize = 12;
    pub(super) const a3: usize = 13;
    pub(super) const a4: usize = 14;
    pub(super) const a5: usize = 15;
    pub(super) const a6: usize = 16;
    pub(super) const a7: usize = 17;
    pub(super) const s2: usize = 18;
    pub(super) const s3: usize = 19;
    pub(super) const s4: usize = 20;
    pub(super) const s5: usize = 21;
    pub(super) const s6: usize = 22;
    pub(super) const s7: usize = 23;
    pub(super) const s8: usize = 24;
    pub(super) const s9: usize = 25;
    pub(super) const s10: usize = 26;
    pub(super) const s11: usize = 27;
    pub(super) const t3: usize = 28;
    pub(super) const t4: usize = 29;
    pub(super) const t5: usize = 30;
    pub(super) const t6: usize = 31;
}

mod fp {
    pub(super) const ft0: usize = 0;
    pub(super) const ft1: usize = 1;
    pub(super) const ft2: usize = 2;
    pub(super) const ft3: usize = 3;
    pub(super) const ft4: usize = 4;
    pub(super) const ft5: usize = 5;
    pub(super) const ft6: usize = 6;
    pub(super) const ft7: usize = 7;
    pub(super) const fs0: usize = 8;
    pub(super) const fs1: usize = 9;
    pub(super) const fa0: usize = 10;
    pub(super) const fa1: usize = 11;
    pub(super) const fa2: usize = 12;
    pub(super) const fa3: usize = 13;
    pub(super) const fa4: usize = 14;
    pub(super) const fa5: usize = 15;
    pub(super) const fa6: usize = 16;
    pub(super) const fa7: usize = 17;
    pub(super) const fs2: usize = 18;
    pub(super) const fs3: usize = 19;
    pub(super) const fs4: usize = 20;
    pub(super) const fs5: usize = 21;
    pub(super) const fs6: usize = 22;
    pub(super) const fs7: usize = 23;
    pub(super) const fs8: usize = 24;
    pub(super) const fs9: usize = 25;
    pub(super) const fs10: usize = 26;
    pub(super) const fs11: usize = 27;
    pub(super) const ft8: usize = 28;
    pub(super) const ft9: usize = 29;
    pub(super) const ft10: usize = 30;
    pub(super) const ft11: usize = 31;
}

mod csr {
    pub(super) const fflags: usize = 1;
    pub(super) const frm: usize = 2;
    pub(super) const fcsr: usize = 3;
}

/// The general purpose registers of the RISC-V ISA
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[repr(usize)]
pub enum GpRegister {
    zero = gp::zero,
    ra = gp::ra,
    sp = gp::sp,
    gp = gp::gp,
    tp = gp::tp,
    t0 = gp::t0,
    t1 = gp::t1,
    t2 = gp::t2,
    s0 = gp::s0,
    s1 = gp::s1,
    a0 = gp::a0,
    a1 = gp::a1,
    a2 = gp::a2,
    a3 = gp::a3,
    a4 = gp::a4,
    a5 = gp::a5,
    a6 = gp::a6,
    a7 = gp::a7,
    s2 = gp::s2,
    s3 = gp::s3,
    s4 = gp::s4,
    s5 = gp::s5,
    s6 = gp::s6,
    s7 = gp::s7,
    s8 = gp::s8,
    s9 = gp::s9,
    s10 = gp::s10,
    s11 = gp::s11,
    t3 = gp::t3,
    t4 = gp::t4,
    t5 = gp::t5,
    t6 = gp::t6,
}

impl GpRegister {
    pub(crate) fn from_usize(number: usize) -> Self {
        assert!(number < 32);
        unsafe { std::mem::transmute::<usize, GpRegister>(number) }
    }
}

/// The floating point register of the RISC-V ISA
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[repr(usize)]
pub enum FpRegister {
    ft0 = fp::ft0,
    ft1 = fp::ft1,
    ft2 = fp::ft2,
    ft3 = fp::ft3,
    ft4 = fp::ft4,
    ft5 = fp::ft5,
    ft6 = fp::ft6,
    ft7 = fp::ft7,
    fs0 = fp::fs0,
    fs1 = fp::fs1,
    fa0 = fp::fa0,
    fa1 = fp::fa1,
    fa2 = fp::fa2,
    fa3 = fp::fa3,
    fa4 = fp::fa4,
    fa5 = fp::fa5,
    fa6 = fp::fa6,
    fa7 = fp::fa7,
    fs2 = fp::fs2,
    fs3 = fp::fs3,
    fs4 = fp::fs4,
    fs5 = fp::fs5,
    fs6 = fp::fs6,
    fs7 = fp::fs7,
    fs8 = fp::fs8,
    fs9 = fp::fs9,
    fs10 = fp::fs10,
    fs11 = fp::fs11,
    ft8 = fp::ft8,
    ft9 = fp::ft9,
    ft10 = fp::ft10,
    ft11 = fp::ft11,
}

impl FpRegister {
    pub(crate) fn from_usize(number: usize) -> Self {
        assert!(number < 32);
        unsafe { std::mem::transmute::<usize, FpRegister>(number) }
    }
}

/// The control/status registers of the RISC-V ISA
#[allow(missing_docs)]
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
#[repr(usize)]
pub enum CsrRegister {
    fflags = csr::fflags,
    frm = csr::frm,
    fcsr = csr::fcsr,
}

impl CsrRegister {
    pub(crate) fn from_usize(number: usize) -> Self {
        match number {
            csr::fflags => CsrRegister::fflags,
            csr::frm => CsrRegister::frm,
            csr::fcsr => CsrRegister::fcsr,
            _ => panic!(),
        }
    }
}

/* syscall related registers */
/// The general purpose register that holds the syscall number
pub const syscall_number: GpRegister = GpRegister::a7;
/// The general purpose registers that hold the syscall arguments
pub const syscall_args: [GpRegister; 6] = [GpRegister::a0, GpRegister::a1, GpRegister::a2, GpRegister::a3, GpRegister::a4, GpRegister::a5];
/// The general purpose register that holds the return value of a syscall
pub const syscall_ret: GpRegister = GpRegister::a0;
