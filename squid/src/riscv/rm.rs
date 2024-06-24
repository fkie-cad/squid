//! The rounding modes of the RISC-V ISA that might appear in the `frm` CSR

/// Round to nearest, ties to even
pub const RNE: u64 = 0b000;
/// Round towards zero
pub const RTZ: u64 = 0b001;
/// Round towards -infinity
pub const RDN: u64 = 0b010;
/// Round towards +infinity
pub const RUP: u64 = 0b011;
/// Round to nearest, ties to max magnitude
pub const RMM: u64 = 0b100;

/// Only valid in instructions but not in fcsr
pub const DYNAMIC: u64 = 0b111;
