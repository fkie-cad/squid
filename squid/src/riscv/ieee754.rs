//! Contains types related to the IEEE754 usage of the RISC-V ISA.

use std::ops::{
    AddAssign,
    SubAssign,
};

use num_traits::{
    bounds::Bounded,
    cast::NumCast,
    float::Float,
};

pub(crate) const NAN_BOX: u64 = 0xFFFFFFFF00000000;
pub(crate) const SINGLE_NAN: u32 = 0x7fc00000;
pub(crate) const DOUBLE_NAN: u64 = 0x7ff8000000000000;

pub(crate) trait RiscvFloat: Float {
    const PRECISION: u32;

    fn is_half(&self) -> bool;
    fn is_odd(&self) -> bool;
    fn is_signaling(&self) -> bool;
    fn riscv_nan() -> Self;

    fn is_special(&self) -> bool {
        self.is_infinite() || self.is_nan() || *self == Self::max_value() || *self == Self::min_value()
    }
}

impl RiscvFloat for f32 {
    const PRECISION: u32 = 24;

    fn is_half(&self) -> bool {
        self.abs() == 0.5f32
    }

    fn is_odd(&self) -> bool {
        (self % 2.0f32).abs() != 0.0f32
    }

    fn is_signaling(&self) -> bool {
        (self.to_bits() & (1u32 << 22)) == 0
    }

    fn riscv_nan() -> Self {
        Self::from_bits(SINGLE_NAN)
    }
}

impl RiscvFloat for f64 {
    const PRECISION: u32 = 53;

    fn is_half(&self) -> bool {
        self.abs() == 0.5f64
    }

    fn is_odd(&self) -> bool {
        (self % 2.0f64).abs() != 0.0f64
    }

    fn is_signaling(&self) -> bool {
        (self.to_bits() & (1u64 << 51)) == 0
    }

    fn riscv_nan() -> Self {
        Self::from_bits(DOUBLE_NAN)
    }
}

/// Round to nearest, tie to even
pub(crate) fn round_nte<T: RiscvFloat + AddAssign + SubAssign>(mut x: T) -> T {
    if x.is_special() {
        return x;
    }

    let (trunk, fract) = (x.trunc(), x.fract());

    if fract.is_half() {
        if trunk.is_odd() {
            x = (x + fract).copysign(x);
        } else {
            x = (x - fract).copysign(x);
        }
    }

    x.round()
}

/// Round towards zero
pub(crate) fn round_tz<T: RiscvFloat + AddAssign + SubAssign>(x: T) -> T {
    if x.is_special() {
        return x;
    }

    if x.is_sign_positive() {
        x.floor()
    } else {
        x.ceil()
    }
}

/// Round down
pub(crate) fn round_dn<T: RiscvFloat + AddAssign + SubAssign>(x: T) -> T {
    if x.is_special() {
        return x;
    }

    x.floor()
}

/// Round up
pub(crate) fn round_up<T: RiscvFloat + AddAssign + SubAssign>(x: T) -> T {
    if x.is_special() {
        return x;
    }

    x.ceil()
}

/// Round to nearest, tie to max magnitude
pub(crate) fn round_nmm<T: RiscvFloat + AddAssign + SubAssign>(mut x: T) -> T {
    if x.is_special() {
        return x;
    }

    let fract = x.fract();

    if fract.is_half() {
        x += fract;
    }

    x.round()
}

pub(crate) fn add<T>(a: T, b: T) -> T
where
    T: RiscvFloat,
{
    if a.is_nan() || b.is_nan() {
        T::riscv_nan()
    } else if a.is_infinite() {
        if b.is_infinite() && (a.is_sign_positive() ^ b.is_sign_positive()) {
            T::riscv_nan()
        } else {
            a
        }
    } else if b.is_infinite() {
        if a.is_infinite() && (a.is_sign_positive() ^ b.is_sign_positive()) {
            T::riscv_nan()
        } else {
            b
        }
    } else {
        a + b
    }
}

pub(crate) fn sub<T: RiscvFloat>(a: T, b: T) -> T {
    if a.is_nan() || b.is_nan() {
        T::riscv_nan()
    } else if a.is_infinite() && b.is_infinite() {
        if a.is_sign_positive() ^ b.is_sign_positive() {
            a
        } else {
            T::riscv_nan()
        }
    } else {
        a - b
    }
}

pub(crate) fn mul<T: RiscvFloat>(a: T, b: T) -> T {
    if (a.is_nan() || b.is_nan()) || (a.is_infinite() && b.is_zero()) || (a.is_zero() && b.is_infinite()) {
        T::riscv_nan()
    } else {
        a * b
    }
}

pub(crate) fn div<T: RiscvFloat>(a: T, b: T) -> T {
    if a.is_nan() || b.is_nan() {
        T::riscv_nan()
    } else if b.is_infinite() {
        if a.is_infinite() {
            T::riscv_nan()
        } else if a.is_sign_positive() ^ b.is_sign_positive() {
            -T::zero()
        } else {
            T::zero()
        }
    } else if a.is_infinite() {
        if a.is_sign_positive() ^ b.is_sign_positive() {
            T::neg_infinity()
        } else {
            T::infinity()
        }
    } else if b.is_zero() {
        if a.is_zero() {
            T::riscv_nan()
        } else if a.is_sign_positive() ^ b.is_sign_positive() {
            T::neg_infinity()
        } else {
            T::infinity()
        }
    } else {
        a / b
    }
}

pub(crate) fn min<T: RiscvFloat>(a: T, b: T) -> T {
    if a.is_nan() || b.is_nan() {
        if a.is_nan() && b.is_nan() {
            T::riscv_nan()
        } else if b.is_nan() {
            a
        } else {
            b
        }
    } else if a.is_zero() && b.is_zero() && a.is_sign_positive() != b.is_sign_positive() {
        -T::zero()
    } else {
        a.min(b)
    }
}

pub(crate) fn max<T: RiscvFloat>(a: T, b: T) -> T {
    if a.is_nan() || b.is_nan() {
        if a.is_nan() && b.is_nan() {
            T::riscv_nan()
        } else if a.is_nan() {
            b
        } else {
            a
        }
    } else if a.is_zero() && b.is_zero() && a.is_sign_positive() != b.is_sign_positive() {
        T::zero()
    } else {
        a.max(b)
    }
}

pub(crate) fn classify<T: RiscvFloat>(a: T) -> u64 {
    let mut mask: u64 = 0;

    if a.is_nan() {
        if a.is_signaling() {
            mask |= 1 << 8;
        } else {
            mask |= 1 << 9;
        }
    } else if a.is_sign_negative() {
        if a.is_infinite() {
            mask |= 1 << 0;
        } else if a.is_subnormal() {
            mask |= 1 << 2;
        } else if a.is_zero() {
            mask |= 1 << 3;
        } else {
            mask |= 1 << 1;
        }
    } else if a.is_infinite() {
        mask |= 1 << 7;
    } else if a.is_subnormal() {
        mask |= 1 << 5;
    } else if a.is_zero() {
        mask |= 1 << 4;
    } else {
        mask |= 1 << 6;
    }

    mask
}

pub(crate) fn convert<F, I>(f: F) -> I
where
    F: RiscvFloat,
    I: Bounded + NumCast,
{
    if f.is_nan() {
        I::max_value()
    } else if f.is_infinite() {
        if f.is_sign_positive() {
            I::max_value()
        } else {
            I::min_value()
        }
    } else if let Some(i) = I::from(f) {
        i
    } else if f.is_sign_positive() {
        I::max_value()
    } else {
        I::min_value()
    }
}
