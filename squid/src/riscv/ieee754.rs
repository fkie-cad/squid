use std::ops::{
    AddAssign,
    SubAssign,
};

use num_traits::{
    bounds::Bounded,
    cast::NumCast,
    float::Float,
};

pub const NAN_BOX: u64 = 0xFFFFFFFF00000000;
pub const SINGLE_NAN: u32 = 0x7fc00000;
pub const DOUBLE_NAN: u64 = 0x7ff8000000000000;

pub trait RiscvFloat: Float {
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
pub fn round_nte<T: RiscvFloat + AddAssign + SubAssign>(mut x: T) -> T {
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
pub fn round_tz<T: RiscvFloat + AddAssign + SubAssign>(x: T) -> T {
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
pub fn round_dn<T: RiscvFloat + AddAssign + SubAssign>(x: T) -> T {
    if x.is_special() {
        return x;
    }

    x.floor()
}

/// Round up
pub fn round_up<T: RiscvFloat + AddAssign + SubAssign>(x: T) -> T {
    if x.is_special() {
        return x;
    }

    x.ceil()
}

/// Round to nearest, tie to max magnitude
pub fn round_nmm<T: RiscvFloat + AddAssign + SubAssign>(mut x: T) -> T {
    if x.is_special() {
        return x;
    }

    let fract = x.fract();

    if fract.is_half() {
        x += fract;
    }

    x.round()
}

pub fn add<T>(a: T, b: T) -> T
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

pub fn sub<T: RiscvFloat>(a: T, b: T) -> T {
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

pub fn mul<T: RiscvFloat>(a: T, b: T) -> T {
    if (a.is_nan() || b.is_nan()) || (a.is_infinite() && b.is_zero()) || (a.is_zero() && b.is_infinite()) {
        T::riscv_nan()
    } else {
        a * b
    }
}

pub fn div<T: RiscvFloat>(a: T, b: T) -> T {
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

pub fn min<T: RiscvFloat>(a: T, b: T) -> T {
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

pub fn max<T: RiscvFloat>(a: T, b: T) -> T {
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

pub fn classify<T: RiscvFloat>(a: T) -> u64 {
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

pub fn convert<F, I>(f: F) -> I
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_nte() {
        assert_eq!(round_nte(0.0f64), 0.0f64);
        assert_eq!(round_nte(-0.0f64), -0.0f64);
        assert_eq!(round_nte(0.5f64), 0.0f64);
        assert_eq!(round_nte(-0.5f64), -0.0f64);
        assert_eq!(round_nte(1.5f64), 2.0f64);
        assert_eq!(round_nte(-1.5f64), -2.0f64);
        assert_eq!(round_nte(2.5f64), 2.0f64);
        assert_eq!(round_nte(-2.5f64), -2.0f64);
    }

    #[test]
    fn test_round_tz() {
        assert_eq!(round_tz(0.0f64), 0.0f64);
        assert_eq!(round_tz(0.5f64), 0.0f64);
        assert_eq!(round_tz(-0.5f64), -0.0f64);
    }

    #[test]
    fn test_round_dn() {
        assert_eq!(round_dn(0.5f64), 0.0f64);
        assert_eq!(round_dn(-0.5f64), -1.0f64);
    }

    #[test]
    fn test_round_up() {
        assert_eq!(round_up(0.5f64), 1.0f64);
        assert_eq!(round_up(-0.5f64), -0.0f64);
    }

    #[test]
    fn test_round_nmm() {
        assert_eq!(round_nmm(0.5f64), 1.0f64);
        assert_eq!(round_nmm(-0.5f64), -1.0f64);
    }

    #[test]
    fn test_riscv_nan() {
        assert!(f32::riscv_nan().is_nan());
        assert!(f64::riscv_nan().is_nan());
    }

    #[test]
    fn convert1() {
        let f = -340282350000000000000000000000000000000.0f32;
        assert_eq!(f, f32::MIN);
        println!("{:#x}", f as i32);
    }

    #[test]
    fn convert2() {
        let f = 2147483600.0f32;
        //      2147483647
        println!("{:#x}", f as i32);
    }

    #[test]
    fn classify32() {
        let f = f32::from_bits(0x7fc00000);
        assert!(f.is_nan());
        assert!(!f.is_signaling());
        assert_eq!(classify(f), 1 << 9);
    }
}
