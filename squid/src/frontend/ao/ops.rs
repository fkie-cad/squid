use crate::{
    event::EventId,
    frontend::{
        Pointer,
        VAddr,
    },
    riscv::register::{
        CsrRegister,
        FpRegister,
        GpRegister,
    },
};

/// The different types of comparisons that can occur in RISC-V code
#[derive(Debug, Clone, Hash)]
pub enum Comparison {
    /// Equality
    Equal,
    
    /// Non-equality
    NotEqual,
    
    /// Compare if one operand is less than the other. If the inner bool is `true` then this
    /// is a signed comparison.
    Less(bool),
    
    /// Compare if one operand is less than or equal than the other. If the inner bool is `true` then this
    /// is a signed comparison.
    LessEqual(bool),
}

/// The different types of registers that can occur in RISC-V code
#[derive(Debug, Clone, Hash)]
pub enum Register {
    /// General purpose register
    Gp(GpRegister),
    
    /// Floating point register
    Fp(FpRegister),
    
    /// Control/status register
    Csr(CsrRegister),
}

impl Register {
    /// Check whether this register is a general purpose register
    pub fn is_gp(&self) -> bool {
        matches!(self, Self::Gp(_))
    }

    /// Check whether this register is a floating point register
    pub fn is_fp(&self) -> bool {
        matches!(self, Self::Fp(_))
    }

    /// Check whether this register is a control/status register
    pub fn is_csr(&self) -> bool {
        matches!(self, Self::Csr(_))
    }
}

/// Every ΑΩ-variable has one of these types
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum VarType {
    /// A 64-bit integer (signed or unsigned). Also used for pointers.
    Number,

    /// A single-precision floating point number
    Float32,

    /// A double-precision floating point number
    Float64,
}

/// An ΑΩ-variable is an [SSA variable](https://en.wikipedia.org/wiki/Static_single-assignment_form) of the ΑΩ IR
#[derive(Debug, Copy, Clone, Hash)]
pub struct Var {
    id: u32,
    typ: VarType,
}

impl Var {
    pub(crate) fn new(id: usize, typ: VarType) -> Self {
        Self {
            id: id as u32,
            typ,
        }
    }

    /// Get the unique ID of this variable (ΑΩ-variables are numbered starting from zero)
    pub fn id(&self) -> usize {
        self.id as usize
    }

    /// Get the type of this variable
    pub fn vartype(&self) -> VarType {
        self.typ
    }

    /// Check whether this variable is a number
    #[inline]
    pub fn is_number(&self) -> bool {
        matches!(&self.typ, VarType::Number)
    }

    /// Check whether this variable is a single-precision float
    #[inline]
    pub fn is_float32(&self) -> bool {
        matches!(&self.typ, VarType::Float32)
    }

    /// Check whether this variable is a double-precision float
    #[inline]
    pub fn is_float64(&self) -> bool {
        matches!(&self.typ, VarType::Float64)
    }
}

/// For operations that have 128-bit results, this determines which 64-bit half to use
#[allow(missing_docs)]
#[derive(Debug, Clone, Hash)]
pub enum Half {
    Lower,
    Upper,
}

/// Some ΑΩ-operations behave differently depending on the signedness of their arguments
#[allow(missing_docs)]
#[derive(Debug, Clone, Hash)]
pub enum Signedness {
    Signed,
    Unsigned,
    Mixed,
}

/// ΑΩ-operations are used to capture the behavior of RISC-V instructions but make
/// every single step explicit.
/// 
/// For example, the RISC-V instruction `add a0, a1, a2` can be broken down into the steps
/// 1. Load register a1
/// 2. Load register a2
/// 3. Perform add
/// 4. Write result to register a0
/// 
/// The ΑΩ IR provides operations for all of the four steps.
/// 
/// You cannot directly synthesize [`Op`]s, you have to use the builder methods
/// in [`BasicBlock`](crate::frontend::ao::BasicBlock).
#[allow(missing_docs)]
#[derive(Debug, Clone, Hash)]
pub enum Op {
    /// A meta-op that signals that a new instruction from the original
    /// binary is being executed.
    NextInstruction {
        vaddr: VAddr,
        //TODO: dwarf data
    },

    /// Store a concrete virtual address `vaddr` that is to be symbolized
    /// in the variable `dst`.
    LoadVirtAddr { dst: Var, vaddr: VAddr },

    /// Copy the value from variable `var` into register `reg`.
    StoreRegister { reg: Register, var: Var },

    /// Store the immediate `imm` in variable `dst`.
    LoadImmediate { dst: Var, imm: u64 },

    /// Jump to the location stored in variable `dst`.
    Jump { dst: Var },

    /// Copy the value from register `reg` into variable `var`.
    LoadRegister { var: Var, reg: Register },

    /// Add `src1` to `src2` and store the result in `dst`.
    Add { dst: Var, src1: Var, src2: Var },

    /// Evaluate `<lhs> <comp> <rhs>` and store a 1 into variable `dst` if it
    /// evaluates to true. Otherwise store 0 into `dst`.
    Compare { dst: Var, lhs: Var, rhs: Var, comp: Comparison },

    /// Jump to the location stored in `dst` if variable `cond` is not equal to zero.
    /// If `cond` is equal to zero execute the next instruction.
    Branch { dst: Var, cond: Var },

    /// Load `size` bytes at address `addr` into variable `dst`.
    /// If `size` is less than 8 then the result is zero-extended
    /// to 64-bits.
    LoadMemory { dst: Var, addr: Var, size: usize },

    /// Treat `src` as a value of `size` bytes, sign-extend it to
    /// 64 bits and store the result in `dst`.
    SignExtend { dst: Var, src: Var, size: usize },

    /// Store the lower `size` bytes of variable `src` into the memory location pointed
    /// to by `addr`.
    StoreMemory { addr: Var, src: Var, size: usize },

    /// Calculate `<src1> ^ <src2>` and store it into variable `dst`.
    Xor { dst: Var, src1: Var, src2: Var },

    /// Calculate `<src1> | <src2>` and store it into variable `dst`.
    Or { dst: Var, src1: Var, src2: Var },

    /// Calculate the bitwise AND of `src1` and `src2` and store it into variable `dst`.
    And { dst: Var, src1: Var, src2: Var },

    /// Calculate `<lhs> - <rhs>` and store the result into variable `dst`.
    Sub { dst: Var, lhs: Var, rhs: Var },

    /// Shift `src` `amount` bits to the left and store the result into variable `dst`.
    /// Only the lower 6 bits of `amount` are taken into consideration.
    ShiftLeft { dst: Var, src: Var, amount: Var },

    /// Shift `src` `amount` bits to the right. If `arithmetic` is true, the shift is arithmetic.
    /// Only the lower 6 bits of `amount` are taken into consideration.
    ShiftRight { dst: Var, src: Var, amount: Var, arithmetic: bool },

    /// Do nothing.
    Nop,

    /// Push the variables `args` in the given order onto the event I/O channel.
    /// If a variable is less than 64-bits wide it is zero extended.
    PushEventArgs { args: Vec<Var> },

    /// Interrupt program execution and yield the event `event` to the application.
    FireEvent { event: EventId },

    /// Copy values from the event I/O channel into the given variables.
    /// It is assumed that all variables are 64-bit integers.
    CollectEventReturns { vars: Vec<Var> },

    /// Treat `src` as a value of `size` bytes, zero-extend it to
    /// 64 bits and store the result in `dst`.
    ZeroExtend { dst: Var, src: Var, size: usize },

    /// Flip all bits of the variable `src` and store the result into variable `dst`.
    Invert { dst: Var, src: Var },

    /// Compute the minimum of `src1` and `src2` and store the result in `dst`.
    /// If `signed` is true, `src1` and `src2` are interpreted as signed integers.
    Min { dst: Var, src1: Var, src2: Var, signs: Signedness },

    /// Compute the maximum of `src1` and `src2` and store the result in `dst`.
    /// If `signed` is true, `src1` and `src2` are interpreted as signed integers.
    Max { dst: Var, src1: Var, src2: Var, signs: Signedness },

    /// Given a single precision floating point value in `src`, convert it to a double
    /// precision floating point value by NaN-boxing it and store it into `dst`.
    NaNBox { dst: Var, src: Var },

    /// Given a bit pattern in `src` that might either be a IEEE754 floating point number
    /// or an integer, reinterpret the bit pattern as a single precision float.
    /// If `src` is larger than 4 bytes then the upper `n - 4` bytes are silently discarded
    /// and the lower 4 bytes are moved into `dst`.
    ReinterpretAsFloat32 { dst: Var, src: Var },

    /// Given a bit pattern in `src` that might either be a IEEE754 floating point number
    /// or an integer, reinterpret the bit pattern as a double precision float.
    /// If `src` is n < 8 bytes long the upper 8 - n bytes are set to zero.
    ReinterpretAsFloat64 { dst: Var, src: Var },

    /// Compute `(src1 * src2) + src3` and store the result into `dst`.
    MultiplyAdd { dst: Var, src1: Var, src2: Var, src3: Var },

    /// Given a double precision floating point value `src`, check that it is NaN-boxed
    /// and extract the boxed single precision float. If `src` is not properly NaN-boxed
    /// set `dst` to NaN instead.
    NaNUnbox { dst: Var, src: Var },

    /// Check if `src` contains a NaN floating point value and convert it into the
    /// RISC-V canonical NaN.
    ConvertNaN { dst: Var, src: Var },

    /// Invert the sign of the value in `src`. Might be integer or float.
    Negate { dst: Var, src: Var },

    /// Multiply `src1` by `src2`. If the sources are floats, `signed` and `half`
    /// will be ignored. If the sources are integers however the product will be
    /// a 128-bit integer. `half` selects which 64-bit half to store into `dst`.
    Multiply { dst: Var, src1: Var, src2: Var, half: Half, signs: Signedness },

    /// Calculate `src1 / src2` and store the result into `dst`.
    Divide { dst: Var, src1: Var, src2: Var, signs: Signedness },

    /// Calculate the square root of `src` and store the result into `dst`.
    Sqrt { dst: Var, src: Var },

    /// Given a variable in `src` reinterpret its bit pattern as a 64-bit integer.
    /// If `src` is n < 8 bytes long the upper 8 - n bytes are set to zero.
    ReinterpretAsInteger { dst: Var, src: Var },

    /// Classify the float in `src` and write the resulting bit pattern into `dst`.
    Classify { dst: Var, src: Var },

    /// Convert a variable `src` into a 32-bit integer of the same numerical
    /// value. The upper 32 bits of `dst` will be set to zero.
    /// `signed` refers to the signedness of `dst`.
    ConvertToInteger32 { dst: Var, src: Var, sign: Signedness },

    /// Round the given floating point number in `src` according to rounding mode `rm`
    /// and store the result into `dst`.
    Round { dst: Var, src: Var, rm: Var },

    /// Convert the integer in `src` to a single-precision floating point number and store
    /// the result in `dst`.
    /// `signed` refers to the signedness of `src`.
    ConvertToFloat32 { dst: Var, src: Var, sign: Signedness },

    /// Convert the integer in `src` to a double-precision floating point number and store
    /// the result in `dst`.
    /// `signed` refers to the signedness of `src`.
    ConvertToFloat64 { dst: Var, src: Var, sign: Signedness },

    /// Convert a variable `src` into a 64-bit integer of the same numerical
    /// value.
    /// `signed` refers to the signedness of `dst`.
    ConvertToInteger64 { dst: Var, src: Var, sign: Signedness },

    /// Calculate `src1 % src2` and store the result in `dst`.
    /// `signs` refers to the signedness of both source variables.
    Remainder { dst: Var, src1: Var, src2: Var, signs: Signedness },

    /// Copies the value of `src` into `dst`.
    Copy { dst: Var, src: Var },

    /// Load the symbol pointer `pointer` into variable `dst`.
    LoadPointer { dst: Var, pointer: Pointer },
}

impl Op {
    /// Check whether the current operation terminates a basic block
    pub fn is_terminator(&self) -> bool {
        matches!(self, Op::Branch { .. } | Op::Jump { .. } | Op::FireEvent { .. })
    }

    /// Return the output variables of this op
    pub fn output_variables(&self) -> Vec<Var> {
        let mut ret = Vec::new();

        match self {
            Op::LoadVirtAddr {
                dst,
                ..
            } => ret.push(*dst),
            Op::LoadImmediate {
                dst,
                ..
            } => ret.push(*dst),
            Op::Add {
                dst,
                ..
            } => ret.push(*dst),
            Op::Compare {
                dst,
                ..
            } => ret.push(*dst),
            Op::LoadMemory {
                dst,
                ..
            } => ret.push(*dst),
            Op::SignExtend {
                dst,
                ..
            } => ret.push(*dst),
            Op::Xor {
                dst,
                ..
            } => ret.push(*dst),
            Op::Or {
                dst,
                ..
            } => ret.push(*dst),
            Op::And {
                dst,
                ..
            } => ret.push(*dst),
            Op::Sub {
                dst,
                ..
            } => ret.push(*dst),
            Op::ShiftLeft {
                dst,
                ..
            } => ret.push(*dst),
            Op::ShiftRight {
                dst,
                ..
            } => ret.push(*dst),
            Op::CollectEventReturns {
                vars,
            } => ret.clone_from(vars),
            Op::ZeroExtend {
                dst,
                ..
            } => ret.push(*dst),
            Op::Invert {
                dst,
                ..
            } => ret.push(*dst),
            Op::Min {
                dst,
                ..
            } => ret.push(*dst),
            Op::Max {
                dst,
                ..
            } => ret.push(*dst),
            Op::NaNBox {
                dst,
                ..
            } => ret.push(*dst),
            Op::ReinterpretAsFloat32 {
                dst,
                ..
            } => ret.push(*dst),
            Op::ReinterpretAsFloat64 {
                dst,
                ..
            } => ret.push(*dst),
            Op::MultiplyAdd {
                dst,
                ..
            } => ret.push(*dst),
            Op::NaNUnbox {
                dst,
                ..
            } => ret.push(*dst),
            Op::ConvertNaN {
                dst,
                ..
            } => ret.push(*dst),
            Op::Negate {
                dst,
                ..
            } => ret.push(*dst),
            Op::Multiply {
                dst,
                ..
            } => ret.push(*dst),
            Op::Divide {
                dst,
                ..
            } => ret.push(*dst),
            Op::Sqrt {
                dst,
                ..
            } => ret.push(*dst),
            Op::ReinterpretAsInteger {
                dst,
                ..
            } => ret.push(*dst),
            Op::Classify {
                dst,
                ..
            } => ret.push(*dst),
            Op::ConvertToInteger32 {
                dst,
                ..
            } => ret.push(*dst),
            Op::Round {
                dst,
                ..
            } => ret.push(*dst),
            Op::ConvertToFloat32 {
                dst,
                ..
            } => ret.push(*dst),
            Op::ConvertToFloat64 {
                dst,
                ..
            } => ret.push(*dst),
            Op::ConvertToInteger64 {
                dst,
                ..
            } => ret.push(*dst),
            Op::Remainder {
                dst,
                ..
            } => ret.push(*dst),
            Op::StoreRegister {
                ..
            } => {},
            Op::Nop => {},
            Op::PushEventArgs {
                ..
            } => {},
            Op::FireEvent {
                ..
            } => {},
            Op::StoreMemory {
                ..
            } => {},
            Op::Branch {
                ..
            } => {},
            Op::Jump {
                ..
            } => {},
            Op::NextInstruction {
                ..
            } => {},
            Op::LoadRegister {
                var,
                ..
            } => ret.push(*var),
            Op::Copy {
                dst,
                ..
            } => ret.push(*dst),
            Op::LoadPointer {
                dst,
                ..
            } => ret.push(*dst),
        }

        ret
    }

    /// Get the input variables used by this op
    pub fn input_variables(&self) -> Vec<Var> {
        let mut ret = Vec::new();

        match self {
            Op::NextInstruction {
                ..
            } => {},
            Op::LoadVirtAddr {
                ..
            } => {},
            Op::StoreRegister {
                var,
                ..
            } => ret.push(*var),
            Op::LoadImmediate {
                ..
            } => {},
            Op::Jump {
                dst,
            } => ret.push(*dst),
            Op::LoadRegister {
                ..
            } => {},
            Op::Remainder {
                src1,
                src2,
                ..
            }
            | Op::Multiply {
                src1,
                src2,
                ..
            }
            | Op::Divide {
                src1,
                src2,
                ..
            }
            | Op::Min {
                src1,
                src2,
                ..
            }
            | Op::Max {
                src1,
                src2,
                ..
            }
            | Op::Xor {
                src1,
                src2,
                ..
            }
            | Op::Or {
                src1,
                src2,
                ..
            }
            | Op::And {
                src1,
                src2,
                ..
            }
            | Op::Add {
                src1,
                src2,
                ..
            } => {
                ret.push(*src1);
                ret.push(*src2);
            },
            Op::ConvertToFloat32 {
                src,
                ..
            }
            | Op::ConvertToFloat64 {
                src,
                ..
            }
            | Op::ConvertToInteger64 {
                src,
                ..
            }
            | Op::SignExtend {
                src,
                ..
            }
            | Op::ZeroExtend {
                src,
                ..
            }
            | Op::Invert {
                src,
                ..
            }
            | Op::NaNBox {
                src,
                ..
            }
            | Op::ReinterpretAsFloat32 {
                src,
                ..
            }
            | Op::ReinterpretAsFloat64 {
                src,
                ..
            }
            | Op::NaNUnbox {
                src,
                ..
            }
            | Op::ConvertNaN {
                src,
                ..
            }
            | Op::Negate {
                src,
                ..
            }
            | Op::Sqrt {
                src,
                ..
            }
            | Op::ReinterpretAsInteger {
                src,
                ..
            }
            | Op::Classify {
                src,
                ..
            }
            | Op::ConvertToInteger32 {
                src,
                ..
            } => ret.push(*src),
            Op::Compare {
                lhs,
                rhs,
                ..
            }
            | Op::Sub {
                lhs,
                rhs,
                ..
            } => {
                ret.push(*lhs);
                ret.push(*rhs);
            },
            Op::ShiftLeft {
                src,
                amount,
                ..
            }
            | Op::ShiftRight {
                src,
                amount,
                ..
            } => {
                ret.push(*src);
                ret.push(*amount);
            },
            Op::Branch {
                dst,
                cond,
            } => {
                ret.push(*dst);
                ret.push(*cond);
            },
            Op::LoadMemory {
                addr,
                ..
            } => ret.push(*addr),
            Op::StoreMemory {
                addr,
                src,
                ..
            } => {
                ret.push(*addr);
                ret.push(*src);
            },
            Op::Nop => {},
            Op::PushEventArgs {
                args,
            } => ret.clone_from(args),
            Op::FireEvent {
                ..
            } => {},
            Op::CollectEventReturns {
                ..
            } => {},
            Op::MultiplyAdd {
                src1,
                src2,
                src3,
                ..
            } => {
                ret.push(*src1);
                ret.push(*src2);
                ret.push(*src3);
            },
            Op::Round {
                src,
                rm,
                ..
            } => {
                ret.push(*src);
                ret.push(*rm);
            },
            Op::Copy {
                src,
                ..
            } => ret.push(*src),
            Op::LoadPointer {
                ..
            } => {},
        }

        ret
    }

    /// Get the input registers used by this op
    pub fn input_register(&self) -> Option<Register> {
        match self {
            Op::LoadRegister {
                reg,
                ..
            } => Some(reg.clone()),
            _ => None,
        }
    }

    /// Get the output registers used by this op
    pub fn output_register(&self) -> Option<Register> {
        match self {
            Op::StoreRegister {
                reg,
                ..
            } => Some(reg.clone()),
            _ => None,
        }
    }
}
