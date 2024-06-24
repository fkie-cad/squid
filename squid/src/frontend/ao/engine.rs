//! Contains the [`Engine`] for execution of ΑΩ-operations

#![allow(clippy::result_large_err)]

use thiserror::Error;

use crate::{
    event::EventId,
    frontend::{
        ao::{
            BasicBlock,
            Comparison,
            Half,
            Op,
            Register,
            Signedness,
            Var,
            VarType,
        },
        Pointer,
        VAddr,
    },
    riscv,
};

const REGISTER_COUNT: usize = 32 + 32 + 1;
fn register_index(reg: &Register) -> usize {
    match reg {
        Register::Gp(reg) => *reg as usize,
        Register::Fp(reg) => 32 + *reg as usize,
        Register::Csr(_) => 64,
    }
}

fn pointer_add(p: &Pointer, i: u64) -> Option<Pointer> {
    match p {
        Pointer::BasicBlock(_) | Pointer::Function(_) | Pointer::Null => None,
        Pointer::Local(p) => {
            let mut ret = p.clone();
            ret.offset += i as usize;
            Some(Pointer::Local(ret))
        },
        Pointer::Global(p) => {
            let mut ret = p.clone();
            ret.offset += i as usize;
            Some(Pointer::Global(ret))
        },
    }
}

fn pointer_sub(p: &Pointer, i: u64) -> Option<Pointer> {
    match p {
        Pointer::BasicBlock(_) | Pointer::Function(_) | Pointer::Null => None,
        Pointer::Local(p) => {
            let mut ret = p.clone();
            ret.offset -= i as usize;
            Some(Pointer::Local(ret))
        },
        Pointer::Global(p) => {
            let mut ret = p.clone();
            ret.offset -= i as usize;
            Some(Pointer::Global(ret))
        },
    }
}

/// This error type shows everything that can go wrong when interpreting ΑΩ operations
#[derive(Error, Debug)]
pub enum EngineError {
    #[error("Invalid type combination: {0:?}")]
    InvalidTypeCombination(Vec<Value>),

    #[error("Encountered a basic block terminator inside a basic block")]
    InvalidBbTerminator,

    #[error("{0:?}")]
    MemoryError(#[from] MemoryError),

    #[error("Invalid operation on given values: {0:?} and {1:?}")]
    InvalidBinaryOp(Value, Value),

    #[error("Invalid operation on value: {0:?}")]
    InvalidUnaryOp(Value),

    #[error("Invalid operand size: {0}")]
    InvalidOpSize(usize),

    #[error("Invalid type for operation: {0:?}")]
    InvalidType(Value),

    #[error("Invalid operation on given values: {0:?}, {1:?} and {2:?}")]
    InvalidTernaryOp(Value, Value, Value),

    #[error("")]
    NotImplemented,
}

/// The concrete value of an ΑΩ-variable.
#[derive(Clone, Debug)]
pub enum Value {
    Unknown,
    VAddr(VAddr),
    Integer(u64),
    FloatSingle(f32),
    FloatDouble(f64),
    Pointer(Pointer),
}

impl Value {
    fn compare(&self, other: &Self, comp: &Comparison) -> Result<Self, EngineError> {
        let result = match (self, other) {
            (Value::VAddr(lhs), Value::VAddr(rhs))
            | (Value::VAddr(lhs), Value::Integer(rhs))
            | (Value::Integer(lhs), Value::VAddr(rhs))
            | (Value::Integer(lhs), Value::Integer(rhs)) => {
                let cond = match comp {
                    Comparison::Equal => *lhs == *rhs,
                    Comparison::NotEqual => *lhs != *rhs,
                    Comparison::Less(signed) => {
                        if *signed {
                            (*lhs as i64) < (*rhs as i64)
                        } else {
                            *lhs < *rhs
                        }
                    },
                    Comparison::LessEqual(signed) => {
                        if *signed {
                            (*lhs as i64) <= (*rhs as i64)
                        } else {
                            *lhs <= *rhs
                        }
                    },
                };

                if cond {
                    Value::Integer(1)
                } else {
                    Value::Integer(0)
                }
            },
            (Value::FloatSingle(lhs), Value::FloatSingle(rhs)) => {
                let cond = match comp {
                    Comparison::Equal => *lhs == *rhs,
                    Comparison::NotEqual => *lhs != *rhs,
                    Comparison::Less(_) => *lhs < *rhs,
                    Comparison::LessEqual(_) => *lhs <= *rhs,
                };

                if cond {
                    Value::Integer(1)
                } else {
                    Value::Integer(0)
                }
            },
            (Value::FloatDouble(lhs), Value::FloatDouble(rhs)) => {
                let cond = match comp {
                    Comparison::Equal => *lhs == *rhs,
                    Comparison::NotEqual => *lhs != *rhs,
                    Comparison::Less(_) => *lhs < *rhs,
                    Comparison::LessEqual(_) => *lhs <= *rhs,
                };

                if cond {
                    Value::Integer(1)
                } else {
                    Value::Integer(0)
                }
            },
            (Value::Pointer(p), Value::Integer(i)) => {
                let cond = match p {
                    Pointer::Null => match comp {
                        Comparison::Equal => 0 == *i,
                        Comparison::NotEqual => 0 != *i,
                        Comparison::Less(signed) => {
                            if *signed {
                                0 < (*i as i64)
                            } else {
                                0 < *i
                            }
                        },
                        Comparison::LessEqual(signed) => {
                            if *signed {
                                0 <= (*i as i64)
                            } else {
                                true
                            }
                        },
                    },
                    _ => return Err(EngineError::InvalidTypeCombination(vec![self.clone(), other.clone()])),
                };

                if cond {
                    Value::Integer(1)
                } else {
                    Value::Integer(0)
                }
            },
            (Value::Integer(i), Value::Pointer(p)) => {
                let cond = match p {
                    Pointer::Null => match comp {
                        Comparison::Equal => *i == 0,
                        Comparison::NotEqual => *i != 0,
                        Comparison::Less(signed) => {
                            if *signed {
                                (*i as i64) < 0
                            } else {
                                false
                            }
                        },
                        Comparison::LessEqual(signed) => {
                            if *signed {
                                (*i as i64) <= 0
                            } else {
                                *i == 0
                            }
                        },
                    },
                    _ => return Err(EngineError::InvalidTypeCombination(vec![self.clone(), other.clone()])),
                };

                if cond {
                    Value::Integer(1)
                } else {
                    Value::Integer(0)
                }
            },
            (_, Value::Unknown) | (Value::Unknown, _) => Value::Unknown,
            _ => return Err(EngineError::InvalidTypeCombination(vec![self.clone(), other.clone()])),
        };

        Ok(result)
    }

    fn calculate_binary<F1, F2, F3, F4, F5>(
        &self,
        other: &Self,
        mut integer_op: F1,
        mut float_single_op: F2,
        mut float_double_op: F3,
        mut pointer_op_l: F4,
        mut pointer_op_r: F5,
    ) -> Result<Self, EngineError>
    where
        F1: FnMut(&u64, &u64) -> Option<u64>,
        F2: FnMut(&f32, &f32) -> Option<f32>,
        F3: FnMut(&f64, &f64) -> Option<f64>,
        F4: FnMut(&Pointer, &u64) -> Option<Pointer>,
        F5: FnMut(&u64, &Pointer) -> Option<Pointer>,
    {
        let result = match (self, other) {
            (Value::Integer(lhs), Value::Integer(rhs)) => Value::Integer(integer_op(lhs, rhs).ok_or(EngineError::InvalidBinaryOp(self.clone(), other.clone()))?),
            (Value::Integer(lhs), Value::VAddr(rhs)) | (Value::VAddr(lhs), Value::Integer(rhs)) | (Value::VAddr(lhs), Value::VAddr(rhs)) => {
                Value::VAddr(integer_op(lhs, rhs).ok_or(EngineError::InvalidBinaryOp(self.clone(), other.clone()))?)
            },
            (Value::FloatSingle(lhs), Value::FloatSingle(rhs)) => Value::FloatSingle(float_single_op(lhs, rhs).ok_or(EngineError::InvalidBinaryOp(self.clone(), other.clone()))?),
            (Value::FloatDouble(lhs), Value::FloatDouble(rhs)) => Value::FloatDouble(float_double_op(lhs, rhs).ok_or(EngineError::InvalidBinaryOp(self.clone(), other.clone()))?),
            (Value::Pointer(a), Value::Integer(b)) => Value::Pointer(pointer_op_l(a, b).ok_or(EngineError::InvalidBinaryOp(self.clone(), other.clone()))?),
            (Value::Integer(a), Value::Pointer(b)) => Value::Pointer(pointer_op_r(a, b).ok_or(EngineError::InvalidBinaryOp(self.clone(), other.clone()))?),
            (_, Value::Unknown) | (Value::Unknown, _) => Value::Unknown,
            _ => return Err(EngineError::InvalidTypeCombination(vec![self.clone(), other.clone()])),
        };

        Ok(result)
    }

    fn calculate_unary<F1, F2, F3, F4>(&self, mut integer_op: F1, mut float_single_op: F2, mut float_double_op: F3, mut pointer_op: F4) -> Result<Self, EngineError>
    where
        F1: FnMut(&u64) -> Option<u64>,
        F2: FnMut(&f32) -> Option<f32>,
        F3: FnMut(&f64) -> Option<f64>,
        F4: FnMut(&Pointer) -> Option<Pointer>,
    {
        let result = match self {
            Value::Unknown => Value::Unknown,
            Value::Integer(value) => Value::Integer(integer_op(value).ok_or(EngineError::InvalidUnaryOp(self.clone()))?),
            Value::VAddr(value) => Value::VAddr(integer_op(value).ok_or(EngineError::InvalidUnaryOp(self.clone()))?),
            Value::FloatSingle(value) => Value::FloatSingle(float_single_op(value).ok_or(EngineError::InvalidUnaryOp(self.clone()))?),
            Value::FloatDouble(value) => Value::FloatDouble(float_double_op(value).ok_or(EngineError::InvalidUnaryOp(self.clone()))?),
            Value::Pointer(pointer) => Value::Pointer(pointer_op(pointer).ok_or(EngineError::InvalidUnaryOp(self.clone()))?),
        };

        Ok(result)
    }

    fn convert<F1, F2, F3, F4>(&self, mut integer_op: F1, mut float_single_op: F2, mut float_double_op: F3, mut pointer_op: F4) -> Result<Self, EngineError>
    where
        F1: FnMut(&u64) -> Option<Value>,
        F2: FnMut(&f32) -> Option<Value>,
        F3: FnMut(&f64) -> Option<Value>,
        F4: FnMut(&Pointer) -> Option<Value>,
    {
        let result = match self {
            Value::Unknown => Value::Unknown,
            Value::VAddr(value) | Value::Integer(value) => integer_op(value).ok_or(EngineError::InvalidUnaryOp(self.clone()))?,
            Value::FloatSingle(value) => float_single_op(value).ok_or(EngineError::InvalidUnaryOp(self.clone()))?,
            Value::FloatDouble(value) => float_double_op(value).ok_or(EngineError::InvalidUnaryOp(self.clone()))?,
            Value::Pointer(pointer) => pointer_op(pointer).ok_or(EngineError::InvalidUnaryOp(self.clone()))?,
        };

        Ok(result)
    }

    fn calculate_ternary<F1, F2, F3>(&self, other1: &Self, other2: &Self, mut integer_op: F1, mut float_single_op: F2, mut float_double_op: F3) -> Result<Self, EngineError>
    where
        F1: FnMut(&u64, &u64, &u64) -> Option<u64>,
        F2: FnMut(&f32, &f32, &f32) -> Option<f32>,
        F3: FnMut(&f64, &f64, &f64) -> Option<f64>,
    {
        let result = match (self, other1, other2) {
            (Value::Unknown, _, _) | (_, Value::Unknown, _) | (_, _, Value::Unknown) => Some(Value::Unknown),
            (Value::Integer(value1), Value::Integer(value2), Value::Integer(value3)) => integer_op(value1, value2, value3).map(Value::Integer),
            (Value::VAddr(value1), Value::VAddr(value2), Value::VAddr(value3))
            | (Value::VAddr(value1), Value::VAddr(value2), Value::Integer(value3))
            | (Value::VAddr(value1), Value::Integer(value2), Value::VAddr(value3))
            | (Value::VAddr(value1), Value::Integer(value2), Value::Integer(value3))
            | (Value::Integer(value1), Value::VAddr(value2), Value::VAddr(value3))
            | (Value::Integer(value1), Value::VAddr(value2), Value::Integer(value3))
            | (Value::Integer(value1), Value::Integer(value2), Value::VAddr(value3)) => integer_op(value1, value2, value3).map(Value::VAddr),
            (Value::FloatSingle(value1), Value::FloatSingle(value2), Value::FloatSingle(value3)) => float_single_op(value1, value2, value3).map(Value::FloatSingle),
            (Value::FloatDouble(value1), Value::FloatDouble(value2), Value::FloatDouble(value3)) => float_double_op(value1, value2, value3).map(Value::FloatDouble),
            _ => return Err(EngineError::InvalidTypeCombination(vec![self.clone(), other1.clone(), other2.clone()])),
        }
        .ok_or(EngineError::InvalidTernaryOp(self.clone(), other1.clone(), other2.clone()))?;

        Ok(result)
    }
}

/// This error type shows everything that can go wrong with the memory component of the [`Engine`].
#[derive(Error, Debug)]
pub enum MemoryError {
    #[error("Out-of-bounds access of {1} bytes at address {0:#x}")]
    Oob(VAddr, usize),

    #[error("{0}")]
    Other(String),
}

/// This trait must be implemented by anything that handles the memory for the [`Engine`].
pub trait MemoryProvider {
    fn load_byte(&self, vaddr: VAddr) -> Result<u8, MemoryError>;
    fn load_hword(&self, vaddr: VAddr) -> Result<u16, MemoryError>;
    fn load_word(&self, vaddr: VAddr) -> Result<u32, MemoryError>;
    fn load_dword(&self, vaddr: VAddr) -> Result<u64, MemoryError>;
    fn store_byte(&mut self, vaddr: VAddr, value: u8) -> Result<(), MemoryError>;
    fn store_hword(&mut self, vaddr: VAddr, value: u16) -> Result<(), MemoryError>;
    fn store_word(&mut self, vaddr: VAddr, value: u32) -> Result<(), MemoryError>;
    fn store_dword(&mut self, vaddr: VAddr, value: u64) -> Result<(), MemoryError>;
    fn translate_pointer(&self, pointer: &Pointer) -> Result<VAddr, MemoryError>;
}

impl MemoryProvider for () {
    fn load_byte(&self, _vaddr: VAddr) -> Result<u8, MemoryError> {
        unimplemented!()
    }

    fn load_hword(&self, _vaddr: VAddr) -> Result<u16, MemoryError> {
        unimplemented!()
    }

    fn load_word(&self, _vaddr: VAddr) -> Result<u32, MemoryError> {
        unimplemented!()
    }

    fn load_dword(&self, _vaddr: VAddr) -> Result<u64, MemoryError> {
        unimplemented!()
    }

    fn store_byte(&mut self, _vaddr: VAddr, _value: u8) -> Result<(), MemoryError> {
        unimplemented!()
    }

    fn store_hword(&mut self, _vaddr: VAddr, _value: u16) -> Result<(), MemoryError> {
        unimplemented!()
    }

    fn store_word(&mut self, _vaddr: VAddr, _value: u32) -> Result<(), MemoryError> {
        unimplemented!()
    }

    fn store_dword(&mut self, _vaddr: VAddr, _value: u64) -> Result<(), MemoryError> {
        unimplemented!()
    }

    fn translate_pointer(&self, _pointer: &Pointer) -> Result<VAddr, MemoryError> {
        unimplemented!()
    }
}

/// After interpreting a [`BasicBlock`], the next basic block to interpret is determined
/// by this enum.
#[derive(Debug)]
pub enum JumpTarget {
    Unknown,
    Next,
    Branch,
    VAddr(VAddr),
    Pointer(Pointer),
}

/// The Engine is an interpreter for ΑΩ-operations and is used to execute basic blocks.
/// After execution you can inspect the concrete values inside registers / memory / ΑΩ-variables.
pub struct Engine<'a, M>
where
    M: MemoryProvider,
{
    bb: &'a BasicBlock,
    vars: Vec<Value>,
    event: Option<EventId>,
    event_channel: Vec<Var>,
    registers: Vec<Value>,
    memory: Option<&'a mut M>,
    jump: Option<JumpTarget>,
}

impl<'a, M> Engine<'a, M>
where
    M: MemoryProvider,
{
    /// Attach this engine to a BasicBlock that you want to execute.
    /// Optionally you can pass a MemoryProvider that handles the memory loads and stores
    /// of the given basic block.
    pub fn attach(bb: &'a BasicBlock, memory: Option<&'a mut M>) -> Self {
        Self {
            bb,
            vars: vec![Value::Unknown; bb.num_variables()],
            event: None,
            event_channel: Vec::new(),
            registers: vec![Value::Unknown; REGISTER_COUNT],
            memory,
            jump: None,
        }
    }

    /// After execution, this is set if the basic block threw an event
    pub fn event(&self) -> Option<EventId> {
        self.event
    }

    /// Access the event channel that the bb wrote to
    pub fn event_channel(&self) -> &[Var] {
        &self.event_channel
    }

    /// Set the contents of a given register to a given value
    pub fn set_register(&mut self, reg: &Register, value: Value) {
        self.registers[register_index(reg)] = value;
    }

    /// Get the contents of a given register
    pub fn get_register(&self, reg: &Register) -> &Value {
        &self.registers[register_index(reg)]
    }

    /// Get the memory subsystem
    pub fn memory(&self) -> Option<&M> {
        self.memory.as_deref()
    }

    /// Get the memory subsystem
    pub fn memory_mut(&mut self) -> Option<&mut M> {
        self.memory.as_deref_mut()
    }

    /// Get the concrete values of all ΑΩ-variables after execution
    pub fn vars(&self) -> &[Value] {
        &self.vars
    }

    /// Get the concrete value of a given ΑΩ-variable after execution
    pub fn var(&self, var: Var) -> &Value {
        &self.vars[var.id()]
    }

    /// Check if the basic block has made a jump during execution
    pub fn jump(&self) -> Option<&JumpTarget> {
        self.jump.as_ref()
    }

    /// Execute all the ΑΩ-operations inside the attached basic block
    #[rustfmt::skip]
    pub fn execute(&mut self) -> Result<(), EngineError> {
        let mut must_end = false;

        for op in self.bb.ops() {
            if must_end {
                return Err(EngineError::InvalidBbTerminator);
            }

            //println!("[engine] executing {:?}", op);

            match op {
                Op::NextInstruction { .. } => {},
                Op::LoadVirtAddr { dst, vaddr } => {
                    self.vars[dst.id()] = Value::VAddr(*vaddr);
                },
                Op::StoreRegister { reg, var } => {
                    self.registers[register_index(reg)] = self.vars[var.id()].clone();
                },
                Op::LoadImmediate { dst, imm } => {
                    self.vars[dst.id()] = Value::Integer(*imm);
                },
                Op::Jump { dst } => {
                    let jump = match &self.vars[dst.id()] {
                        Value::Unknown => JumpTarget::Unknown,
                        Value::VAddr(vaddr) => JumpTarget::VAddr(*vaddr),
                        _value @ Value::Integer(_vaddr) => {
                            #[cfg(test)]
                            {
                                JumpTarget::VAddr(*_vaddr)
                            }
                            #[cfg(not(test))]
                            {
                                return Err(EngineError::InvalidType(_value.clone()));
                            }
                        },
                        Value::Pointer(pointer) => JumpTarget::Pointer(pointer.clone()),
                        value => return Err(EngineError::InvalidType(value.clone()))
                    };
                    self.jump = Some(jump);
                    must_end = true;
                },
                Op::LoadRegister { var, reg } => {
                    self.vars[var.id()] = self.registers[register_index(reg)].clone();
                },
                Op::Add { dst, src1, src2 } => {
                    self.vars[dst.id()] = self.vars[src1.id()].calculate_binary(
                        &self.vars[src2.id()],
                        |&a, &b| Some(a.wrapping_add(b)),
                        |&a, &b| Some(riscv::ieee754::add(a, b)),
                        |&a, &b| Some(riscv::ieee754::add(a, b)),
                        |p, &i| pointer_add(p, i),
                        |&i, p| pointer_add(p, i)
                    )?;
                },
                Op::Compare { dst, lhs, rhs, comp } => {
                    self.vars[dst.id()] = self.vars[lhs.id()].compare(
                        &self.vars[rhs.id()],
                        comp,
                    )?;
                },
                Op::Branch { cond, .. } => {
                    let jump = match &self.vars[cond.id()] {
                        Value::Unknown => JumpTarget::Unknown,
                        Value::Integer(i) => match *i {
                            0 => JumpTarget::Next,
                            1 => JumpTarget::Branch,
                            _ => unreachable!(),
                        },
                        value => return Err(EngineError::InvalidType(value.clone()))
                    };
                    self.jump = Some(jump);
                    must_end = true;
                },
                Op::LoadMemory { dst, addr, size } => {
                    let value = if let Some(memory) = &self.memory {
                        let vaddr = match &self.vars[addr.id()] {
                            Value::Integer(addr) => *addr,
                            Value::VAddr(vaddr) => *vaddr,
                            Value::Pointer(pointer) => memory.translate_pointer(pointer)?,
                            addr => return Err(EngineError::InvalidType(addr.clone())),
                        };

                        let value = match *size {
                            1 => memory.load_byte(vaddr)? as u64,
                            2 => memory.load_hword(vaddr)? as u64,
                            4 => memory.load_word(vaddr)? as u64,
                            8 => memory.load_dword(vaddr)?,
                            size => return Err(EngineError::InvalidOpSize(size)),
                        };

                        match dst.vartype() {
                            VarType::Number => Value::Integer(value),
                            VarType::Float32 => Value::FloatSingle(f32::from_bits(value as u32)),
                            VarType::Float64 => Value::FloatDouble(f64::from_bits(value)),
                        }
                    } else {
                        Value::Unknown
                    };
                    self.vars[dst.id()] = value;
                },
                Op::SignExtend { dst, src, size } => {
                    self.vars[dst.id()] = self.vars[src.id()].calculate_unary(
                        |&value| match *size {
                            1 => Some(value as u8 as i8 as i64 as u64),
                            2 => Some(value as u16 as i16 as i64 as u64),
                            4 => Some(value as u32 as i32 as i64 as u64),
                            _ => None,
                        },
                        |_| None,
                        |_| None,
                        |_| None,
                    )?;
                },
                Op::StoreMemory { addr, src, size } => {
                    if let Some(memory) = &mut self.memory {
                        let vaddr = match &self.vars[addr.id()] {
                            Value::Integer(addr) => *addr,
                            Value::VAddr(vaddr) => *vaddr,
                            Value::Pointer(pointer) => memory.translate_pointer(pointer)?,
                            addr => return Err(EngineError::InvalidType(addr.clone())),
                        };
                        let value = match &self.vars[src.id()] {
                            Value::Unknown => continue,
                            Value::VAddr(value) => *value,
                            Value::Integer(value) => *value,
                            Value::FloatSingle(value) => {
                                if *size != 4 {
                                    return Err(EngineError::InvalidOpSize(*size));
                                }

                                value.to_bits() as u64
                            },
                            Value::FloatDouble(value) => {
                                if *size != 8 {
                                    return Err(EngineError::InvalidOpSize(*size));
                                }

                                value.to_bits()
                            },
                            Value::Pointer(pointer) => memory.translate_pointer(pointer)?,
                        };

                        match *size {
                            1 => memory.store_byte(vaddr, value as u8)?,
                            2 => memory.store_hword(vaddr, value as u16)?,
                            4 => memory.store_word(vaddr, value as u32)?,
                            8 => memory.store_dword(vaddr, value)?,
                            size => return Err(EngineError::InvalidOpSize(size)),
                        }
                    }
                },
                Op::Xor { dst, src1, src2 } => {
                    self.vars[dst.id()] = self.vars[src1.id()].calculate_binary(
                        &self.vars[src2.id()],
                        |&a, &b| Some(a ^ b),
                        |_, _| None,
                        |_, _| None,
                        |_, _| None,
                        |_, _| None,
                    )?;
                },
                Op::Or { dst, src1, src2 } => {
                    self.vars[dst.id()] = self.vars[src1.id()].calculate_binary(
                        &self.vars[src2.id()],
                        |&a, &b| Some(a | b),
                        |_ ,_| None,
                        |_ ,_| None,
                        |_ ,_| None,
                        |_ ,_| None,
                    )?;
                },
                Op::And { dst, src1, src2 } => {
                    self.vars[dst.id()] = self.vars[src1.id()].calculate_binary(
                        &self.vars[src2.id()],
                        |&a, &b| Some(a & b),
                        |_ ,_| None,
                        |_ ,_| None,
                        |_ ,_| None,
                        |_ ,_| None,
                    )?;
                },
                Op::Sub { dst, lhs, rhs } => {
                    self.vars[dst.id()] = self.vars[lhs.id()].calculate_binary(
                        &self.vars[rhs.id()],
                        |&a, &b| Some(a.wrapping_sub(b)),
                        |&a, &b| Some(riscv::ieee754::sub(a, b)),
                        |&a, &b| Some(riscv::ieee754::sub(a, b)),
                        |p, &i| pointer_sub(p, i),
                        |_ ,_| None,
                    )?;
                },
                Op::ShiftLeft { dst, src, amount } => {
                    let amount = match &self.vars[amount.id()] {
                        Value::VAddr(addr) => Some(*addr),
                        Value::Integer(value) => Some(*value),
                        Value::Unknown => None,
                        value => return Err(EngineError::InvalidType(value.clone())),
                    };
                    if let Some(amount) = amount {
                        self.vars[dst.id()] = self.vars[src.id()].calculate_unary(
                            |&value| Some(value.wrapping_shl(amount as u32)),
                            |_| None,
                            |_| None,
                            |_| None,
                        )?;
                    } else {
                        self.vars[dst.id()] = Value::Unknown;
                    }

                },
                Op::ShiftRight { dst, src, amount, arithmetic } => {
                    let amount = match &self.vars[amount.id()] {
                        Value::VAddr(addr) => Some(*addr),
                        Value::Integer(value) => Some(*value),
                        Value::Unknown => None,
                        value => return Err(EngineError::InvalidType(value.clone())),
                    };
                    if let Some(amount) = amount {
                        self.vars[dst.id()] = self.vars[src.id()].calculate_unary(
                            |&value| if *arithmetic {
                                Some(((value as i64).wrapping_shr(amount as u32)) as u64)
                            } else {
                                Some(value.wrapping_shr(amount as u32))
                            },
                            |_| None,
                            |_| None,
                            |_| None,
                        )?;
                    } else {
                        self.vars[dst.id()] = Value::Unknown;
                    }
                },
                Op::Nop => {},
                Op::PushEventArgs { args } => {
                    for arg in args {
                        self.event_channel.push(*arg);
                    }
                },
                Op::FireEvent { event } => {
                    self.event = Some(*event);
                    self.jump = Some(JumpTarget::Next);
                    must_end = true;
                },
                Op::CollectEventReturns { vars } => {
                    for var in vars {
                        self.vars[var.id()] = Value::Unknown;
                    }
                },
                Op::ZeroExtend { dst, src, size } => {
                    self.vars[dst.id()] = self.vars[src.id()].calculate_unary(
                        |&value| match *size {
                            1 => Some(value as u8 as u64),
                            2 => Some(value as u16 as u64),
                            4 => Some(value as u32 as u64),
                            _ => None,
                        },
                        |_| None,
                        |_| None,
                        |_| None,
                    )?;
                },
                Op::Invert { dst, src } => {
                    self.vars[dst.id()] = self.vars[src.id()].calculate_unary(
                        |&value| Some(!value),
                        |_| None,
                        |_| None,
                        |_| None,
                    )?;
                },
                Op::Min { dst, src1, src2, signs } => {
                    self.vars[dst.id()] = self.vars[src1.id()].calculate_binary(
                        &self.vars[src2.id()],
                        |&a, &b| match signs {
                            Signedness::Mixed |
                            Signedness::Signed => Some(std::cmp::min(a as i64, b as i64) as u64),
                            Signedness::Unsigned => Some(std::cmp::min(a, b)),
                        },
                        |&a, &b| Some(riscv::ieee754::min(a, b)),
                        |&a, &b| Some(riscv::ieee754::min(a, b)),
                        |_, _| None,
                        |_, _| None,
                    )?;
                },
                Op::Max { dst, src1, src2, signs } => {
                    self.vars[dst.id()] = self.vars[src1.id()].calculate_binary(
                        &self.vars[src2.id()],
                        |&a, &b| match signs {
                            Signedness::Mixed |
                            Signedness::Signed => Some(std::cmp::max(a as i64, b as i64) as u64),
                            Signedness::Unsigned => Some(std::cmp::max(a, b))
                        },
                        |&a, &b| Some(riscv::ieee754::max(a, b)),
                        |&a, &b| Some(riscv::ieee754::max(a, b)),
                        |_, _| None,
                        |_, _| None,
                    )?;
                },
                Op::NaNBox { dst, src } => {
                    self.vars[dst.id()] = self.vars[src.id()].convert(
                        |&value| if (value & riscv::ieee754::NAN_BOX) != 0 {
                            None
                        } else {
                            Some(Value::FloatDouble(f64::from_bits(riscv::ieee754::NAN_BOX | value)))
                        },
                        |&value| Some(Value::FloatDouble(f64::from_bits(riscv::ieee754::NAN_BOX | value.to_bits() as u64))),
                        |_| None,
                        |_| None,
                    )?;
                },
                Op::ReinterpretAsFloat32 { dst, src } => {
                    self.vars[dst.id()] = self.vars[src.id()].convert(
                        |&value| Some(Value::FloatSingle(f32::from_bits(value as u32))),
                        |&value| Some(Value::FloatSingle(value)),
                        |&value| Some(Value::FloatSingle(f32::from_bits(value.to_bits() as u32))),
                        |_| None,
                    )?;
                },
                Op::ReinterpretAsFloat64 { dst, src } => {
                    self.vars[dst.id()] = self.vars[src.id()].convert(
                        |&value| Some(Value::FloatDouble(f64::from_bits(value))),
                        |&value| Some(Value::FloatDouble(f64::from_bits(value.to_bits() as u64))),
                        |&value| Some(Value::FloatDouble(value)),
                        |_| None,
                    )?;
                },
                Op::MultiplyAdd { dst, src1, src2, src3 } => {
                    self.vars[dst.id()] = self.vars[src1.id()].calculate_ternary(
                        &self.vars[src2.id()],
                        &self.vars[src3.id()],
                        |&value1, &value2, &value3| Some(value1.wrapping_mul(value2).wrapping_add(value3)),
                        |&value1, &value2, &value3| Some(value1.mul_add(value2, value3)),
                        |&value1, &value2, &value3| Some(value1.mul_add(value2, value3)),
                    )?;
                },
                Op::NaNUnbox { dst, src } => {
                    self.vars[dst.id()] = self.vars[src.id()].convert(
                        |_| None,
                        |_| None,
                        |&value| {
                            let value = value.to_bits();

                            if (value & riscv::ieee754::NAN_BOX) != riscv::ieee754::NAN_BOX {
                                Some(Value::FloatSingle(f32::from_bits(riscv::ieee754::SINGLE_NAN)))
                            } else {
                                Some(Value::FloatSingle(f32::from_bits(value as u32)))
                            }
                        },
                        |_| None,
                    )?;
                },
                Op::ConvertNaN { dst, src } => {
                    self.vars[dst.id()] = self.vars[src.id()].calculate_unary(
                        |_| None,
                        |&value| if value.is_nan() {
                            Some(f32::from_bits(riscv::ieee754::SINGLE_NAN))
                        } else {
                            Some(value)
                        },
                        |&value| if value.is_nan() {
                            Some(f64::from_bits(riscv::ieee754::DOUBLE_NAN))
                        } else {
                            Some(value)
                        },
                        |_| None,
                    )?;
                },
                Op::Negate { dst, src } => {
                    self.vars[dst.id()] = self.vars[src.id()].calculate_unary(
                        |&value| Some(0 - value),
                        |&value| Some(-value),
                        |&value| Some(-value),
                        |_| None,
                    )?;
                },
                Op::Multiply { dst, src1, src2, half, signs } => {
                    self.vars[dst.id()] = self.vars[src1.id()].calculate_binary(
                        &self.vars[src2.id()],
                        |&value1, &value2| {
                            let (value1, value2) = match signs {
                                Signedness::Unsigned => (value1 as u128, value2 as u128),
                                Signedness::Signed => (value1 as i64 as i128 as u128, value2 as i64 as i128 as u128),
                                Signedness::Mixed => (value1 as i64 as i128 as u128, value2 as u128),
                            };
                            let result = value1.wrapping_mul(value2);
                            match half {
                                Half::Lower => Some(result as u64),
                                Half::Upper => Some((result >> 64) as u64),
                            }
                        },
                        |&value1, &value2| Some(riscv::ieee754::mul(value1, value2)),
                        |&value1, &value2| Some(riscv::ieee754::mul(value1, value2)),
                        |_, _| None,
                        |_, _| None,
                    )?;
                },
                Op::Divide { dst, src1, src2, signs } => {
                    self.vars[dst.id()] = self.vars[src1.id()].calculate_binary(
                        &self.vars[src2.id()],
                        |&value1, &value2| {
                            if value2 == 0 {
                                return Some(u64::MAX);
                            }
                            let result = match signs {
                                Signedness::Mixed |
                                Signedness::Signed => {
                                    if value1 == (1u64 << 63) && value2 == u64::MAX {
                                        return Some(value1);
                                    }

                                    (value1 as i64 / value2 as i64) as u64
                                },
                                Signedness::Unsigned => value1 / value2,
                            };
                            Some(result)
                        },
                        |&value1, &value2| Some(riscv::ieee754::div(value1, value2)),
                        |&value1, &value2| Some(riscv::ieee754::div(value1, value2)),
                        |_, _| None,
                        |_, _| None,
                    )?;
                },
                Op::Sqrt { dst, src } => {
                    self.vars[dst.id()] = self.vars[src.id()].calculate_unary(
                        |&value| Some((value as f64).sqrt() as u64),
                        |&value| Some(value.sqrt()),
                        |&value| Some(value.sqrt()),
                        |_| None,
                    )?;
                },
                Op::ReinterpretAsInteger { dst, src } => {
                    self.vars[dst.id()] = self.vars[src.id()].convert(
                        |&value| Some(Value::Integer(value)),
                        |&value| Some(Value::Integer(value.to_bits() as u64)),
                        |&value| Some(Value::Integer(value.to_bits())),
                        |_| None,
                    )?;
                },
                Op::Classify { dst, src } => {
                    self.vars[dst.id()] = self.vars[src.id()].convert(
                        |_| None,
                        |&value| Some(Value::Integer(riscv::ieee754::classify(value))),
                        |&value| Some(Value::Integer(riscv::ieee754::classify(value))),
                        |_| None,
                    )?;
                },
                Op::ConvertToInteger32 { dst, src, sign } => {
                    self.vars[dst.id()] = self.vars[src.id()].convert(
                        |&value| Some(Value::Integer(value as u32 as u64)),
                        |&value| match sign {
                            Signedness::Mixed |
                            Signedness::Signed => Some(Value::Integer(riscv::ieee754::convert::<f32, i32>(value) as u64)),
                            Signedness::Unsigned => Some(Value::Integer(riscv::ieee754::convert::<f32, u32>(value) as u64)),
                        },
                        |&value| match sign {
                            Signedness::Mixed |
                            Signedness::Signed => Some(Value::Integer(riscv::ieee754::convert::<f64, i32>(value) as u64)),
                            Signedness::Unsigned => Some(Value::Integer(riscv::ieee754::convert::<f64, u32>(value) as u64)),
                        },
                        |_| None,
                    )?;
                },
                Op::Round { dst, src, rm } => {
                    let rm = match &self.vars[rm.id()] {
                        Value::Unknown => None,
                        Value::Integer(rm) => Some(*rm),
                        value => return Err(EngineError::InvalidType(value.clone())),
                    };

                    if let Some(rm) = rm {
                        self.vars[dst.id()] = self.vars[src.id()].calculate_unary(
                            |_| None,
                            |&value| match rm {
                                riscv::rm::RNE => Some(riscv::ieee754::round_nte(value)),
                                riscv::rm::RTZ => Some(riscv::ieee754::round_tz(value)),
                                riscv::rm::RDN => Some(riscv::ieee754::round_dn(value)),
                                riscv::rm::RUP => Some(riscv::ieee754::round_up(value)),
                                riscv::rm::RMM => Some(riscv::ieee754::round_nmm(value)),
                                _ => None
                            },
                            |&value| match rm {
                                riscv::rm::RNE => Some(riscv::ieee754::round_nte(value)),
                                riscv::rm::RTZ => Some(riscv::ieee754::round_tz(value)),
                                riscv::rm::RDN => Some(riscv::ieee754::round_dn(value)),
                                riscv::rm::RUP => Some(riscv::ieee754::round_up(value)),
                                riscv::rm::RMM => Some(riscv::ieee754::round_nmm(value)),
                                _ => None
                            },
                            |_| None,
                        )?;
                    } else {
                        self.vars[dst.id()] = Value::Unknown;
                    }
                },
                Op::ConvertToFloat32 { dst, src, sign } => {
                    self.vars[dst.id()] = self.vars[src.id()].convert(
                        |&value| match sign {
                            Signedness::Mixed |
                            Signedness::Signed => Some(Value::FloatSingle(value as i64 as f32)),
                            Signedness::Unsigned => Some(Value::FloatSingle(value as f32)),
                        },
                        |&value| Some(Value::FloatSingle(value)),
                        |&value| Some(Value::FloatSingle(value as f32)),
                        |_| None,
                    )?;
                },
                Op::ConvertToFloat64 { dst, src, sign } => {
                    self.vars[dst.id()] = self.vars[src.id()].convert(
                        |&value| match sign {
                            Signedness::Mixed |
                            Signedness::Signed => Some(Value::FloatDouble(value as i64 as f64)),
                            Signedness::Unsigned => Some(Value::FloatDouble(value as f64)),
                        },
                        |&value| Some(Value::FloatDouble(value as f64)),
                        |&value| Some(Value::FloatDouble(value)),
                        |_| None,
                    )?;
                },
                Op::ConvertToInteger64 { dst, src, sign } => {
                    self.vars[dst.id()] = self.vars[src.id()].convert(
                        |&value| Some(Value::Integer(value)),
                        |&value| match sign {
                            Signedness::Mixed |
                            Signedness::Signed => Some(Value::Integer(riscv::ieee754::convert::<f32, i64>(value) as u64)),
                            Signedness::Unsigned => Some(Value::Integer(riscv::ieee754::convert::<f32, u64>(value))),
                        },
                        |&value| match sign {
                            Signedness::Mixed |
                            Signedness::Signed => Some(Value::Integer(riscv::ieee754::convert::<f64, i64>(value) as u64)),
                            Signedness::Unsigned => Some(Value::Integer(riscv::ieee754::convert::<f64, u64>(value))),
                        },
                        |_| None,
                    )?;
                },
                Op::Remainder { dst, src1, src2, signs } => {
                    self.vars[dst.id()] = self.vars[src1.id()].calculate_binary(
                        &self.vars[src2.id()],
                        |&value1, &value2| {
                            if value2 == 0 {
                                return Some(value1);
                            }
                            let result = match signs {
                                Signedness::Mixed |
                                Signedness::Signed => {
                                    if value1 == (1u64 << 63) && value2 == u64::MAX {
                                        return Some(0);
                                    }

                                    (value1 as i64 % value2 as i64) as u64
                                },
                                Signedness::Unsigned => value1 % value2,
                            };
                            Some(result)
                        },
                        |&value1, &value2| Some(riscv::ieee754::div(value1, value2)),
                        |&value1, &value2| Some(riscv::ieee754::div(value1, value2)),
                        |_, _| None,
                        |_, _| None,
                    )?;
                },
                Op::Copy { dst, src } => {
                    self.vars[dst.id()] = self.vars[src.id()].clone();
                },
                Op::LoadPointer { dst, pointer } => {
                    self.vars[dst.id()] = Value::Pointer(pointer.clone());
                },
            }
        }

        Ok(())
    }
}
