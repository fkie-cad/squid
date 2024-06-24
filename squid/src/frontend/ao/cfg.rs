use std::collections::HashSet;

use paste::paste;
use thiserror::Error;

use crate::{
    event::EventId,
    frontend::{
        ao::{
            error::AoError,
            ops::{
                Comparison,
                Half,
                Op,
                Register,
                Signedness,
                Var,
                VarType,
            },
        },
        idmap::{
            idmap_functions,
            HasId,
            HasIdMut,
            Id,
            IdMap,
            IdMapValues,
            IdMapValuesMut,
        },
        Pointer,
        VAddr,
    },
    riscv::register::{
        CsrRegister,
        FpRegister,
        GpRegister,
    },
};

/// This error type shows everything that can go wrong when synthesizing basic blocks or CFGs.
#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum CFGError {
    #[error("Invalid entry: {0}")]
    InvalidEntry(Id),

    #[error("Basic block has no id")]
    NoId,

    #[error("Basic block is empty")]
    BasicBlockEmpty(Id),

    #[error("CFG is empty")]
    CfgEmpty,

    #[error("Basic block {0} has invalid edge target: {1}")]
    InvalidTarget(Id, Id),

    #[error("Found terminator in the midst of basic block")]
    InvalidTerminator(Id),

    #[error("The basic block does not end with a terminator and has no next basic block")]
    NoNextBasicBlock(Id),

    #[error("Multiple next basic blocks found")]
    MultipleNextBasicBlocks(Id),
}

/// An Edge is an edge in the CFG
#[derive(Debug, Clone, PartialEq, Hash)]
pub enum Edge {
    /// The "next" edge points to the basic block that immediately follows the source basic block
    /// in linear memory.
    Next(Id),

    /// The "jump" edge points to a basic block that can only be reached by an overwite of the program counter
    /// by a branch or a jump (or a switch).
    Jump(Id),
}

impl Edge {
    /// The destination basic block of this edge
    pub fn target(&self) -> Id {
        match self {
            Edge::Next(id) | Edge::Jump(id) => *id,
        }
    }
}

/// A BasicBlock is a sequence of ΑΩ-operations that run uninterrupted
#[derive(Debug, Clone, Hash)]
pub struct BasicBlock {
    id: Id,
    vaddr: Option<VAddr>,
    ops: Vec<Op>,
    cursor: usize,
    var_cursor: usize,
    edges: Vec<Edge>,
}

impl BasicBlock {
    /// Create a new BasicBlock without a virtual address
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            id: Id::default(),
            vaddr: None,
            ops: Vec::new(),
            cursor: 0,
            var_cursor: 0,
            edges: Vec::new(),
        }
    }

    /// Delete all ΑΩ-operations, edges and reset this BasicBlock
    pub fn clear(&mut self) {
        self.ops.clear();
        self.cursor = 0;
        self.var_cursor = 0;
        self.edges.clear();
    }

    /// Create a new BasicBlock at the given virtual address
    pub fn at_vaddr(vaddr: VAddr) -> Self {
        Self {
            id: Id::default(),
            vaddr: Some(vaddr),
            ops: Vec::new(),
            cursor: 0,
            var_cursor: 0,
            edges: Vec::new(),
        }
    }

    /// Change the virtual address of this basic block
    pub fn set_vaddr(&mut self, vaddr: VAddr) {
        self.vaddr = Some(vaddr);
    }

    /// The outgoing edges of this basic block
    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }

    /// The outgoing edges of this basic block
    pub fn edges_mut(&mut self) -> &mut [Edge] {
        &mut self.edges
    }

    /// Add an outgoing edge to this basic block
    pub fn add_edge(&mut self, edge: Edge) {
        if !self.edges.contains(&edge) {
            self.edges.push(edge);
        }
    }

    /// Delete an outgoing edge from this basic block
    pub fn delete_edge(&mut self, id: Id) -> Option<Edge> {
        for i in 0..self.edges.len() {
            if self.edges[i].target() == id {
                let edge = self.edges.remove(i);
                return Some(edge);
            }
        }

        None
    }

    /// Check if this basic block has an outgoing `Edge::Next` edge and return its destination
    pub fn next_basic_block(&self) -> Option<Id> {
        for edge in &self.edges {
            if let Edge::Next(id) = edge {
                return Some(*id);
            }
        }

        None
    }

    /// Check if this basic block has an outgoing `Edge::Jump` edge and return its destination
    pub fn jump_target(&self) -> Option<Id> {
        for edge in &self.edges {
            if let Edge::Jump(id) = edge {
                return Some(*id);
            }
        }

        None
    }

    /// Get the ΑΩ-operations in this basic block
    pub fn ops(&self) -> &[Op] {
        &self.ops
    }

    /// Get the virtual address of this basic block. Not every basic block must have a virtual address.
    pub fn vaddr(&self) -> Option<VAddr> {
        self.vaddr
    }

    /// Update the op cursor
    pub fn set_cursor(&mut self, idx: usize) {
        assert!(idx <= self.ops.len());
        self.cursor = idx;
    }

    /// Set the op cursor to the end of the op list. This enables appending ops.
    pub fn move_cursor_beyond_end(&mut self) {
        self.cursor = self.ops.len();
    }

    /// Increment the op cursor. Return `false` if the cursor already points to the last op.
    pub fn move_cursor_forward(&mut self) -> bool {
        if self.cursor >= self.ops.len().saturating_sub(1) {
            false
        } else {
            self.cursor += 1;
            true
        }
    }

    /// Decrement the op cursor. Return `false` if the cursor already is at the first op.
    pub fn move_cursor_backwards(&mut self) -> bool {
        if self.cursor > 0 {
            self.cursor -= 1;
            true
        } else {
            false
        }
    }

    /// Get the ΑΩ-operation at the current cursor position
    pub fn cursor_op(&self) -> Option<&Op> {
        self.ops.get(self.cursor)
    }

    /// Get the ΑΩ-operation at the current cursor position
    pub fn cursor_op_mut(&mut self) -> Option<&mut Op> {
        self.ops.get_mut(self.cursor)
    }

    /// Get the current op cursor position
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Get the number of different ΑΩ-variables in use by this basic block
    pub fn num_variables(&self) -> usize {
        self.var_cursor
    }

    /// Delete and return the ΑΩ-operation at the current cursor position
    pub fn delete_op(&mut self) -> Op {
        let op = self.ops.remove(self.cursor);
        self.cursor = std::cmp::min(self.cursor, self.ops.len());
        op
    }

    pub(crate) fn replace_op(&mut self, new_op: Op) -> Op {
        let old = self.ops[self.cursor].clone();
        self.ops[self.cursor] = new_op;
        old
    }

    /// Check whether this basic block ends with an op that explicitly overwrites the program counter (unconditionally)
    pub fn has_continuous_flow(&self) -> bool {
        !matches!(self.ops().last(), Some(Op::Jump { .. }))
    }

    /// Verify the internal state of this basic block and its operations
    pub fn verify(&self) -> Result<(), CFGError> {
        if self.id == Id::default() {
            return Err(CFGError::NoId);
        }

        if self.ops.is_empty() {
            return Err(CFGError::BasicBlockEmpty(self.id));
        }

        /* Check valid edges composition */
        let mut num_next = 0;

        for edge in self.edges() {
            if let Edge::Next(_) = edge {
                num_next += 1;
            }
        }

        if num_next > 1 || (self.edges.len() > 2 && num_next > 0) {
            return Err(CFGError::MultipleNextBasicBlocks(self.id));
        }

        /* Check that basic block ends with a terminator as the last operation */
        let mut must_end = false;

        for op in self.ops() {
            if must_end {
                return Err(CFGError::InvalidTerminator(self.id));
            }

            if op.is_terminator() {
                must_end = true;
            }
        }

        if !must_end && num_next != 1 {
            return Err(CFGError::NoNextBasicBlock(self.id));
        }

        Ok(())
    }

    /// Split this basic block in two by splitting the list of ΑΩ-operations at the current cursor position.
    /// Note that this leaves the current basic block with no edges, all the edges belong to the returned basic block.
    pub fn split(&mut self) -> Self {
        let ops = self.ops.split_off(self.cursor);
        let var_cursor = self.var_cursor;
        let edges = self.edges.drain(..).collect();

        BasicBlock {
            id: Id::default(),
            vaddr: None,
            ops,
            cursor: 0,
            var_cursor,
            edges,
        }
    }
}

impl HasId for BasicBlock {
    fn id(&self) -> Id {
        self.id
    }
}

impl HasIdMut for BasicBlock {
    fn id_mut(&mut self) -> &mut Id {
        &mut self.id
    }
}

#[allow(missing_docs)]
/// Synthesizing instructions for ΑΩ-operations. Each ΑΩ-operation has a corresponding method.
impl BasicBlock {
    fn next_variable(&mut self, typ: VarType) -> Var {
        let var = self.var_cursor;
        self.var_cursor = var.checked_add(1).expect("Ran out of possible variable ids");
        Var::new(var, typ)
    }

    fn insert_op(&mut self, op: Op) {
        self.ops.insert(self.cursor, op);
        self.cursor += 1;
    }

    pub(crate) fn next_instruction(&mut self, vaddr: VAddr) {
        self.insert_op(Op::NextInstruction {
            vaddr,
        });
    }

    pub(crate) fn load_virt_addr(&mut self, vaddr: VAddr) -> Var {
        let dst = self.next_variable(VarType::Number);
        self.insert_op(Op::LoadVirtAddr {
            dst,
            vaddr,
        });
        dst
    }

    fn store_register(&mut self, reg: Register, var: Var) {
        self.insert_op(Op::StoreRegister {
            reg,
            var,
        })
    }

    pub fn store_gp_register(&mut self, reg: GpRegister, var: Var) -> Result<(), AoError> {
        if !var.is_number() {
            return Err(AoError::InvalidVarType("Attempted to store a non-number into a general purpose register".to_string()));
        }

        if reg != GpRegister::zero {
            self.store_register(Register::Gp(reg), var);
        }

        Ok(())
    }

    pub fn load_immediate(&mut self, imm: u64) -> Var {
        let dst = self.next_variable(VarType::Number);
        self.insert_op(Op::LoadImmediate {
            dst,
            imm,
        });
        dst
    }

    pub fn jump(&mut self, dst: Var) -> Result<(), AoError> {
        if !dst.is_number() {
            return Err(AoError::InvalidVarType("Cannot jump to a floating point value".to_string()));
        }

        self.insert_op(Op::Jump {
            dst,
        });

        Ok(())
    }

    fn load_register(&mut self, reg: Register) -> Var {
        let var = match &reg {
            Register::Csr(_) | Register::Gp(_) => self.next_variable(VarType::Number),
            Register::Fp(_) => self.next_variable(VarType::Float64),
        };
        self.insert_op(Op::LoadRegister {
            var,
            reg,
        });
        var
    }

    pub fn load_gp_register(&mut self, reg: GpRegister) -> Var {
        if reg == GpRegister::zero {
            self.load_immediate(0)
        } else {
            self.load_register(Register::Gp(reg))
        }
    }

    pub fn add(&mut self, src1: Var, src2: Var) -> Result<Var, AoError> {
        if src1.vartype() != src2.vartype() {
            return Err(AoError::InvalidVarType(format!("Addition of variables with incompatible types: {:?} and {:?}", src1.vartype(), src2.vartype())));
        }
        let dst = self.next_variable(src1.vartype());
        self.insert_op(Op::Add {
            dst,
            src1,
            src2,
        });
        Ok(dst)
    }

    pub fn compare(&mut self, lhs: Var, rhs: Var, comp: Comparison) -> Result<Var, AoError> {
        if lhs.vartype() != rhs.vartype() {
            return Err(AoError::InvalidVarType(format!("Comparison of variables with incompatible types: {:?} and {:?}", lhs.vartype(), rhs.vartype())));
        }
        let dst = self.next_variable(VarType::Number);
        self.insert_op(Op::Compare {
            dst,
            lhs,
            rhs,
            comp,
        });
        Ok(dst)
    }

    pub fn branch(&mut self, dst: Var, cond: Var) -> Result<(), AoError> {
        if !cond.is_number() {
            return Err(AoError::InvalidVarType("Condition of a branch must be a number".to_string()));
        } else if !dst.is_number() {
            return Err(AoError::InvalidVarType("Branch target cannot be a float".to_string()));
        }
        self.insert_op(Op::Branch {
            dst,
            cond,
        });
        Ok(())
    }

    fn load_memory(&mut self, addr: Var, size: usize, typ: VarType) -> Var {
        let dst = self.next_variable(typ);
        self.insert_op(Op::LoadMemory {
            dst,
            addr,
            size,
        });
        dst
    }

    pub fn load_byte(&mut self, addr: Var) -> Result<Var, AoError> {
        if !addr.is_number() {
            return Err(AoError::InvalidVarType("Address of memory load must be a number".to_string()));
        }
        Ok(self.load_memory(addr, 1, VarType::Number))
    }

    pub fn load_hword(&mut self, addr: Var) -> Result<Var, AoError> {
        if !addr.is_number() {
            return Err(AoError::InvalidVarType("Address of memory load must be a number".to_string()));
        }
        Ok(self.load_memory(addr, 2, VarType::Number))
    }

    pub fn load_word(&mut self, addr: Var) -> Result<Var, AoError> {
        Ok(self.load_memory(addr, 4, VarType::Number))
    }

    pub fn load_dword(&mut self, addr: Var) -> Result<Var, AoError> {
        if !addr.is_number() {
            return Err(AoError::InvalidVarType("Address of memory load must be a number".to_string()));
        }
        Ok(self.load_memory(addr, 8, VarType::Number))
    }

    pub fn load_float32(&mut self, addr: Var) -> Result<Var, AoError> {
        if !addr.is_number() {
            return Err(AoError::InvalidVarType("Address of memory load must be a number".to_string()));
        }
        Ok(self.load_memory(addr, 4, VarType::Float32))
    }

    pub fn load_float64(&mut self, addr: Var) -> Result<Var, AoError> {
        if !addr.is_number() {
            return Err(AoError::InvalidVarType("Address of memory load must be a number".to_string()));
        }
        Ok(self.load_memory(addr, 8, VarType::Float64))
    }

    pub fn sign_extend(&mut self, src: Var, size: usize) -> Result<Var, AoError> {
        if !src.is_number() {
            return Err(AoError::InvalidVarType("Can only sign-extend numbers".to_string()));
        } else if !matches!(size, 1 | 2 | 4) {
            return Err(AoError::InvalidOpSize(size));
        }
        let dst = self.next_variable(VarType::Number);
        self.insert_op(Op::SignExtend {
            dst,
            src,
            size,
        });
        Ok(dst)
    }

    fn store_memory(&mut self, addr: Var, src: Var, size: usize) {
        self.insert_op(Op::StoreMemory {
            addr,
            src,
            size,
        });
    }

    pub fn store_byte(&mut self, addr: Var, src: Var) -> Result<(), AoError> {
        if !addr.is_number() {
            return Err(AoError::InvalidVarType("Address of memory store must be a number".to_string()));
        } else if !src.is_number() {
            return Err(AoError::InvalidVarType("Expected a number for byte store".to_string()));
        }
        self.store_memory(addr, src, 1);
        Ok(())
    }

    pub fn store_hword(&mut self, addr: Var, src: Var) -> Result<(), AoError> {
        if !addr.is_number() {
            return Err(AoError::InvalidVarType("Address of memory store must be a number".to_string()));
        } else if !src.is_number() {
            return Err(AoError::InvalidVarType("Expected a number for hword store".to_string()));
        }
        self.store_memory(addr, src, 2);
        Ok(())
    }

    pub fn store_word(&mut self, addr: Var, src: Var) -> Result<(), AoError> {
        if !addr.is_number() {
            return Err(AoError::InvalidVarType("Address of memory store must be a number".to_string()));
        } else if !src.is_number() {
            return Err(AoError::InvalidVarType("Expected a number for word store".to_string()));
        }
        self.store_memory(addr, src, 4);
        Ok(())
    }

    pub fn store_dword(&mut self, addr: Var, src: Var) -> Result<(), AoError> {
        if !addr.is_number() {
            return Err(AoError::InvalidVarType("Address of memory store must be a number".to_string()));
        } else if !src.is_number() {
            return Err(AoError::InvalidVarType("Expected a number for dword store".to_string()));
        }
        self.store_memory(addr, src, 8);
        Ok(())
    }

    pub fn store_float32(&mut self, addr: Var, src: Var) -> Result<(), AoError> {
        if !addr.is_number() {
            return Err(AoError::InvalidVarType("Address of memory store must be a number".to_string()));
        } else if !src.is_float32() {
            return Err(AoError::InvalidVarType("Expected a float32 for float store".to_string()));
        }
        self.store_memory(addr, src, 4);
        Ok(())
    }

    pub fn store_float64(&mut self, addr: Var, src: Var) -> Result<(), AoError> {
        if !addr.is_number() {
            return Err(AoError::InvalidVarType("Address of memory store must be a number".to_string()));
        } else if !src.is_float64() {
            return Err(AoError::InvalidVarType("Expected a float64 for float store".to_string()));
        }
        self.store_memory(addr, src, 8);
        Ok(())
    }

    pub fn xor(&mut self, src1: Var, src2: Var) -> Result<Var, AoError> {
        if !src1.is_number() || !src2.is_number() {
            return Err(AoError::InvalidVarType("Can only XOR two numbers together".to_string()));
        }
        let dst = self.next_variable(VarType::Number);
        self.insert_op(Op::Xor {
            dst,
            src1,
            src2,
        });
        Ok(dst)
    }

    pub fn or(&mut self, src1: Var, src2: Var) -> Result<Var, AoError> {
        if !src1.is_number() || !src2.is_number() {
            return Err(AoError::InvalidVarType("Can only OR two numbers together".to_string()));
        }
        let dst = self.next_variable(VarType::Number);
        self.insert_op(Op::Or {
            dst,
            src1,
            src2,
        });
        Ok(dst)
    }

    pub fn and(&mut self, src1: Var, src2: Var) -> Result<Var, AoError> {
        if !src1.is_number() || !src2.is_number() {
            return Err(AoError::InvalidVarType("Can only AND two numbers together".to_string()));
        }
        let dst = self.next_variable(VarType::Number);
        self.insert_op(Op::And {
            dst,
            src1,
            src2,
        });
        Ok(dst)
    }

    pub fn sub(&mut self, lhs: Var, rhs: Var) -> Result<Var, AoError> {
        if lhs.vartype() != rhs.vartype() {
            return Err(AoError::InvalidVarType("Subtraction of variables with different types".to_string()));
        }
        let dst = self.next_variable(lhs.vartype());
        self.insert_op(Op::Sub {
            dst,
            lhs,
            rhs,
        });
        Ok(dst)
    }

    pub fn shift_left(&mut self, src: Var, amount: Var) -> Result<Var, AoError> {
        if !src.is_number() || !amount.is_number() {
            return Err(AoError::InvalidVarType("Can only bitshift numbers".to_string()));
        }
        let dst = self.next_variable(VarType::Number);
        self.insert_op(Op::ShiftLeft {
            dst,
            src,
            amount,
        });
        Ok(dst)
    }

    fn shift_right(&mut self, src: Var, amount: Var, arithmetic: bool) -> Result<Var, AoError> {
        if !src.is_number() || !amount.is_number() {
            return Err(AoError::InvalidVarType("Can only bitshift numbers".to_string()));
        }
        let dst = self.next_variable(VarType::Number);
        self.insert_op(Op::ShiftRight {
            dst,
            src,
            amount,
            arithmetic,
        });
        Ok(dst)
    }

    pub fn shift_right_arithmetic(&mut self, src: Var, amount: Var) -> Result<Var, AoError> {
        self.shift_right(src, amount, true)
    }

    pub fn shift_right_logical(&mut self, src: Var, amount: Var) -> Result<Var, AoError> {
        self.shift_right(src, amount, false)
    }

    pub fn nop(&mut self) {
        self.insert_op(Op::Nop);
    }

    pub fn push_event_args<V: Into<Vec<Var>>>(&mut self, args: V) {
        let args = args.into();
        self.insert_op(Op::PushEventArgs {
            args,
        });
    }

    pub fn fire_event(&mut self, event: EventId) {
        self.insert_op(Op::FireEvent {
            event,
        });
    }

    pub fn collect_event_returns(&mut self, num: usize) -> Vec<Var> {
        let mut vars = Vec::with_capacity(num);

        for _ in 0..num {
            vars.push(self.next_variable(VarType::Number));
        }

        self.insert_op(Op::CollectEventReturns {
            vars: vars.clone(),
        });

        vars
    }

    pub fn zero_extend(&mut self, src: Var, size: usize) -> Result<Var, AoError> {
        if !src.is_number() {
            return Err(AoError::InvalidVarType("Can only zero-extend numbers".to_string()));
        } else if !matches!(size, 1 | 2 | 4) {
            return Err(AoError::InvalidOpSize(size));
        }
        let dst = self.next_variable(VarType::Number);
        self.insert_op(Op::ZeroExtend {
            dst,
            src,
            size,
        });
        Ok(dst)
    }

    pub fn load_csr(&mut self, csr: CsrRegister) -> Result<Var, AoError> {
        let value = self.load_register(Register::Csr(csr));
        macro_rules! get_partial_csr {
            ($num_bits:expr, $shift:expr) => {{
                let shift = ($shift) as u64;
                let pattern = u64::MAX >> (64 - ($num_bits));
                let mut value = value;

                if shift > 0 {
                    let amount = self.load_immediate(shift);
                    value = self.shift_right_logical(value, amount)?;
                }

                let mask = self.load_immediate(pattern);
                self.and(value, mask)?
            }};
        }
        let ret = match csr {
            CsrRegister::fflags => get_partial_csr!(5, 0),
            CsrRegister::frm => get_partial_csr!(3, 5),
            CsrRegister::fcsr => get_partial_csr!(8, 0),
        };
        Ok(ret)
    }

    pub fn store_csr(&mut self, csr: CsrRegister, new_value: Var) -> Result<(), AoError> {
        if !new_value.is_number() {
            return Err(AoError::InvalidVarType("Can only store numbers into a csr register".to_string()));
        }
        let reg = Register::Csr(csr);
        macro_rules! set_partial_csr {
            ($num_bits:expr, $shift:expr) => {{
                let shift = ($shift) as u64;
                let pattern = u64::MAX >> (64 - ($num_bits));

                let old_value = self.load_register(reg.clone());
                let del_mask = self.load_immediate(!(pattern << shift));
                let old_value = self.and(old_value, del_mask)?;

                let mask = self.load_immediate(pattern);
                let mut new_value = self.and(new_value, mask)?;

                if shift > 0 {
                    let amount = self.load_immediate(shift);
                    new_value = self.shift_left(new_value, amount)?;
                }

                self.or(old_value, new_value)?
            }};
        }
        let new_value = match csr {
            CsrRegister::fflags => set_partial_csr!(5, 0),
            CsrRegister::frm => set_partial_csr!(3, 5),
            CsrRegister::fcsr => set_partial_csr!(8, 0),
        };
        self.store_register(reg, new_value);
        Ok(())
    }

    pub fn invert(&mut self, src: Var) -> Result<Var, AoError> {
        if !src.is_number() {
            return Err(AoError::InvalidVarType("Can invert only numbers".to_string()));
        }
        let dst = self.next_variable(VarType::Number);
        self.insert_op(Op::Invert {
            dst,
            src,
        });
        Ok(dst)
    }

    fn minimum(&mut self, src1: Var, src2: Var, signs: Signedness, typ: VarType) -> Var {
        let dst = self.next_variable(typ);
        self.insert_op(Op::Min {
            dst,
            src1,
            src2,
            signs,
        });
        dst
    }

    pub fn minimum_number(&mut self, src1: Var, src2: Var, signs: Signedness) -> Result<Var, AoError> {
        if !src1.is_number() || !src2.is_number() {
            return Err(AoError::InvalidVarType("Arguments for minimum_number are not numbers".to_string()));
        }
        Ok(self.minimum(src1, src2, signs, VarType::Number))
    }

    pub fn minimum_float(&mut self, src1: Var, src2: Var) -> Result<Var, AoError> {
        if src1.vartype() != src2.vartype() {
            return Err(AoError::InvalidVarType("Arguments for minimum must be of same type".to_string()));
        } else if src1.is_number() {
            return Err(AoError::InvalidVarType("Arguments for minimum_float are not floats".to_string()));
        }
        Ok(self.minimum(src1, src2, Signedness::Unsigned, src1.vartype()))
    }

    fn maximum(&mut self, src1: Var, src2: Var, signs: Signedness, typ: VarType) -> Var {
        let dst = self.next_variable(typ);
        self.insert_op(Op::Max {
            dst,
            src1,
            src2,
            signs,
        });
        dst
    }

    pub fn maximum_number(&mut self, src1: Var, src2: Var, signs: Signedness) -> Result<Var, AoError> {
        if !src1.is_number() || !src2.is_number() {
            return Err(AoError::InvalidVarType("Arguments for maximum_number are not numbers".to_string()));
        }
        Ok(self.maximum(src1, src2, signs, VarType::Number))
    }

    pub fn maximum_float(&mut self, src1: Var, src2: Var) -> Result<Var, AoError> {
        if src1.vartype() != src2.vartype() {
            return Err(AoError::InvalidVarType("Arguments for maximum_float must be of same type".to_string()));
        } else if src1.is_number() {
            return Err(AoError::InvalidVarType("Arguments for maximum_float are not floats".to_string()));
        }
        Ok(self.maximum(src1, src2, Signedness::Unsigned, src1.vartype()))
    }

    pub fn nan_box(&mut self, src: Var) -> Result<Var, AoError> {
        if !src.is_float32() {
            return Err(AoError::InvalidVarType("Can only nan-box float32".to_string()));
        }
        let dst = self.next_variable(VarType::Float64);
        self.insert_op(Op::NaNBox {
            dst,
            src,
        });
        Ok(dst)
    }

    pub fn store_fp_register(&mut self, reg: FpRegister, var: Var) -> Result<(), AoError> {
        if !var.is_float64() {
            return Err(AoError::InvalidVarType("Attempted to store a non-float64 into a floating point register".to_string()));
        }
        let reg = Register::Fp(reg);
        self.store_register(reg, var);
        Ok(())
    }

    pub fn load_fp_register(&mut self, reg: FpRegister) -> Var {
        self.load_register(Register::Fp(reg))
    }

    pub fn reinterpret_as_float32(&mut self, src: Var) -> Var {
        let dst = self.next_variable(VarType::Float32);
        self.insert_op(Op::ReinterpretAsFloat32 {
            dst,
            src,
        });
        dst
    }

    pub fn reinterpret_as_float64(&mut self, src: Var) -> Result<Var, AoError> {
        if src.is_float32() {
            return Err(AoError::InvalidVarType("Cannot reinterpret float32 as float64".to_string()));
        }
        let dst = self.next_variable(VarType::Float64);
        self.insert_op(Op::ReinterpretAsFloat64 {
            dst,
            src,
        });
        Ok(dst)
    }

    pub fn multiply_add(&mut self, src1: Var, src2: Var, src3: Var) -> Result<Var, AoError> {
        if src1.vartype() != src2.vartype() || src2.vartype() != src3.vartype() {
            return Err(AoError::InvalidVarType("Arguments for multiply_add have different types".to_string()));
        } else if src1.is_number() {
            return Err(AoError::InvalidVarType("Arguments for multiply_add must be floats".to_string()));
        }
        let dst = self.next_variable(src1.vartype());
        self.insert_op(Op::MultiplyAdd {
            dst,
            src1,
            src2,
            src3,
        });
        Ok(dst)
    }

    pub fn nan_unbox(&mut self, src: Var) -> Result<Var, AoError> {
        if !src.is_float64() {
            return Err(AoError::InvalidVarType("Argument for nan_unbox is not a float64".to_string()));
        }
        let dst = self.next_variable(VarType::Float32);
        self.insert_op(Op::NaNUnbox {
            dst,
            src,
        });
        Ok(dst)
    }

    pub fn convert_nan(&mut self, src: Var) -> Result<Var, AoError> {
        if src.is_number() {
            return Err(AoError::InvalidVarType("Argument for convert_nan must be float".to_string()));
        }
        let dst = self.next_variable(src.vartype());
        self.insert_op(Op::ConvertNaN {
            dst,
            src,
        });
        Ok(dst)
    }

    pub fn negate(&mut self, src: Var) -> Var {
        let dst = self.next_variable(src.vartype());
        self.insert_op(Op::Negate {
            dst,
            src,
        });
        dst
    }

    fn multiply(&mut self, src1: Var, src2: Var, half: Half, signs: Signedness, typ: VarType) -> Var {
        let dst = self.next_variable(typ);
        self.insert_op(Op::Multiply {
            dst,
            src1,
            src2,
            half,
            signs,
        });
        dst
    }

    pub fn multiply_float(&mut self, src1: Var, src2: Var) -> Result<Var, AoError> {
        if src1.vartype() != src2.vartype() {
            return Err(AoError::InvalidVarType("Arguments for multiply_float have different types".to_string()));
        } else if src1.is_number() {
            return Err(AoError::InvalidVarType("Arguments for multiply_float are not floats".to_string()));
        }
        Ok(self.multiply(src1, src2, Half::Lower, Signedness::Unsigned, src1.vartype()))
    }

    pub fn multiply_number(&mut self, src1: Var, src2: Var, half: Half, signs: Signedness) -> Result<Var, AoError> {
        if src1.vartype() != src2.vartype() {
            return Err(AoError::InvalidVarType("Arguments for multiply_number have different types".to_string()));
        } else if !src1.is_number() {
            return Err(AoError::InvalidVarType("Arguments for multiply_number are not numbers".to_string()));
        }
        Ok(self.multiply(src1, src2, half, signs, VarType::Number))
    }

    fn divide(&mut self, src1: Var, src2: Var, signs: Signedness, typ: VarType) -> Var {
        let dst = self.next_variable(typ);
        self.insert_op(Op::Divide {
            dst,
            src1,
            src2,
            signs,
        });
        dst
    }

    pub fn divide_float(&mut self, src1: Var, src2: Var) -> Result<Var, AoError> {
        if src1.vartype() != src2.vartype() {
            return Err(AoError::InvalidVarType("Arguments for divide_float have different types".to_string()));
        } else if src1.is_number() {
            return Err(AoError::InvalidVarType("Arguments for divide_float are not floats".to_string()));
        }
        Ok(self.divide(src1, src2, Signedness::Unsigned, src1.vartype()))
    }

    pub fn divide_number(&mut self, src1: Var, src2: Var, signs: Signedness) -> Result<Var, AoError> {
        if src1.vartype() != src2.vartype() {
            return Err(AoError::InvalidVarType("Arguments for divide_number have different types".to_string()));
        } else if !src1.is_number() {
            return Err(AoError::InvalidVarType("Arguments for divide_number are not numbers".to_string()));
        }
        Ok(self.divide(src1, src2, signs, VarType::Number))
    }

    pub fn sqrt(&mut self, src: Var) -> Result<Var, AoError> {
        if src.is_number() {
            return Err(AoError::InvalidVarType("sqrt of number is not supported".to_string()));
        }
        let dst = self.next_variable(src.vartype());
        self.insert_op(Op::Sqrt {
            dst,
            src,
        });
        Ok(dst)
    }

    pub fn reinterpret_as_number(&mut self, src: Var) -> Result<Var, AoError> {
        let dst = self.next_variable(VarType::Number);
        self.insert_op(Op::ReinterpretAsInteger {
            dst,
            src,
        });
        Ok(dst)
    }

    pub fn classify(&mut self, src: Var) -> Result<Var, AoError> {
        if src.is_number() {
            return Err(AoError::InvalidVarType("Attempted classify on number".to_string()));
        }
        let dst = self.next_variable(VarType::Number);
        self.insert_op(Op::Classify {
            dst,
            src,
        });
        Ok(dst)
    }

    pub fn convert_to_integer32(&mut self, src: Var, sign: Signedness) -> Var {
        let dst = self.next_variable(VarType::Number);
        self.insert_op(Op::ConvertToInteger32 {
            dst,
            src,
            sign,
        });
        dst
    }

    pub fn round(&mut self, src: Var, rm: Var) -> Result<Var, AoError> {
        if src.is_number() {
            return Err(AoError::InvalidVarType("Can only round floats".to_string()));
        } else if !rm.is_number() {
            return Err(AoError::InvalidVarType("Rounding mode for round must be a number".to_string()));
        }
        let dst = self.next_variable(src.vartype());
        self.insert_op(Op::Round {
            dst,
            src,
            rm,
        });
        Ok(dst)
    }

    pub fn convert_to_float32(&mut self, src: Var, sign: Signedness) -> Var {
        let dst = self.next_variable(VarType::Float32);
        self.insert_op(Op::ConvertToFloat32 {
            dst,
            src,
            sign,
        });
        dst
    }

    pub fn convert_to_float64(&mut self, src: Var, sign: Signedness) -> Var {
        let dst = self.next_variable(VarType::Float64);
        self.insert_op(Op::ConvertToFloat64 {
            dst,
            src,
            sign,
        });
        dst
    }

    pub fn convert_to_integer64(&mut self, src: Var, sign: Signedness) -> Var {
        let dst = self.next_variable(VarType::Number);
        self.insert_op(Op::ConvertToInteger64 {
            dst,
            src,
            sign,
        });
        dst
    }

    fn remainder(&mut self, src1: Var, src2: Var, signs: Signedness, typ: VarType) -> Var {
        let dst = self.next_variable(typ);
        self.insert_op(Op::Remainder {
            dst,
            src1,
            src2,
            signs,
        });
        dst
    }

    /* Not yet supported:
    pub fn remainder_float(&mut self, src1: Var, src2: Var) -> Result<Var, AoError> {
        if src1.vartype() != src2.vartype() {
            return Err(AoError::InvalidVarType("Arguments for remainder_float have different types".to_string()));
        } else if src1.is_number() {
            return Err(AoError::InvalidVarType("Arguments for remainder_float are not floats".to_string()));
        }
        Ok(self.remainder(src1, src2, Signedness::Unsigned, src1.vartype()))
    }
    */

    pub fn remainder_number(&mut self, src1: Var, src2: Var, signs: Signedness) -> Result<Var, AoError> {
        if src1.vartype() != src2.vartype() {
            return Err(AoError::InvalidVarType("Arguments for remainder_number have different types".to_string()));
        } else if !src1.is_number() {
            return Err(AoError::InvalidVarType("Arguments for remainder_number are not numbers".to_string()));
        }
        Ok(self.remainder(src1, src2, signs, VarType::Number))
    }

    pub fn copy(&mut self, src: Var) -> Var {
        let dst = self.next_variable(src.vartype());
        self.insert_op(Op::Copy {
            dst,
            src,
        });
        dst
    }

    pub fn load_pointer(&mut self, pointer: Pointer) -> Var {
        let dst = self.next_variable(VarType::Number);
        self.insert_op(Op::LoadPointer {
            dst,
            pointer,
        });
        dst
    }
}

/// The Control Flow Graph of a function
#[derive(Clone, Debug, Hash)]
pub struct CFG {
    idmap: IdMap<BasicBlock>,
    entry: Id,
    cursor: usize,
}

idmap_functions!(CFG, BasicBlock, basic_block);

impl CFG {
    /// Create a new, empty CFG
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            idmap: IdMap::new(),
            entry: Id::default(),
            cursor: 0,
        }
    }

    /// Delete all basic blocks in this CFG and reset its state
    pub fn clear(&mut self) {
        self.idmap.clear();
        self.entry = Id::default();
        self.cursor = 0;
    }

    /// Insert a basic block in this CFG and assign it an ID that is returned by this function
    pub fn add_basic_block(&mut self, bb: BasicBlock) -> Id {
        self.idmap.insert(bb)
    }

    /// Get the entrypoint basic block of this CFG
    pub fn entry(&self) -> Id {
        self.entry
    }

    /// Change the entrypoint basic block of this CFG
    pub fn set_entry(&mut self, id: Id) {
        self.entry = id;
    }

    pub(crate) fn verify(&self) -> Result<bool, CFGError> {
        /* Check if entry was set */
        if self.entry == Id::default() {
            return Err(CFGError::InvalidEntry(self.entry));
        }

        /* Check that we have basic blocks */
        if self.idmap.is_empty() {
            return Err(CFGError::CfgEmpty);
        }

        let ids: HashSet<Id> = self.iter_basic_blocks().map(|x| x.id()).collect();

        /* Check that entry points to an existing block */
        if !ids.contains(&self.entry) {
            return Err(CFGError::InvalidEntry(self.entry));
        }

        /* Check that all basic blocks are valid */
        for bb in self.iter_basic_blocks() {
            bb.verify()?;
        }

        /* Check that all edge targets are valid */
        for bb in self.iter_basic_blocks() {
            for edge in bb.edges() {
                if !ids.contains(&edge.target()) {
                    return Err(CFGError::InvalidTarget(bb.id(), edge.target()));
                }
            }
        }

        /* Check reachability */
        let mut visited = HashSet::new();
        let mut stack = Vec::new();

        stack.push(self.entry);

        while let Some(bb) = stack.pop() {
            visited.insert(bb);

            for edge in self.basic_block(bb).unwrap().edges() {
                let target = edge.target();

                if !visited.contains(&target) {
                    stack.push(target);
                }
            }
        }

        Ok(ids.difference(&visited).next().is_none())
    }
}
