use std::collections::{
    HashMap,
    HashSet,
};

use squid_ewe::ListingFunction;

use crate::{
    event::EventPool,
    frontend::{
        ao::{
            cfg::{
                BasicBlock,
                Edge,
                CFG,
            },
            error::AoError,
            events::{
                EVENT_BREAKPOINT,
                EVENT_SYSCALL,
            },
            func::Function,
            ArithmeticBehavior,
            Comparison,
            Half,
            Signedness,
        },
        idmap::{
            HasId,
            Id,
        },
        VAddr,
    },
    riscv::{
        instr::{
            decode,
            InstructionSet,
            CSR,
            RV32A,
            RV32D,
            RV32F,
            RV32I,
            RV32M,
            RV64A,
            RV64D,
            RV64F,
            RV64I,
            RV64M,
        },
        register::{
            CsrRegister,
            FpRegister,
            GpRegister,
        },
        rm,
    },
};

#[derive(Debug, PartialEq)]
enum UnresolvedEdge {
    Next(VAddr),
    Jump(VAddr),
}

impl UnresolvedEdge {
    fn addr(&self) -> VAddr {
        match self {
            UnresolvedEdge::Next(addr) | UnresolvedEdge::Jump(addr) => *addr,
        }
    }
}

pub(crate) struct Lifter {
    cfg: CFG,
    bb_boundaries: HashSet<VAddr>,
    strict_mode: bool,
    edges: HashMap<VAddr, Vec<UnresolvedEdge>>,
    func_start: VAddr,
    func_end: VAddr,
    seen_terminator: bool,
}

impl Lifter {
    pub(crate) fn lift(
        base_addr: VAddr,
        section_end: VAddr,
        data: &[u8],
        func: Option<&ListingFunction>,
        event_pool: &mut EventPool,
    ) -> Result<Function, AoError> {
        assert_eq!(data.len() % 4, 0);

        let mut lifter = Self::new(base_addr, base_addr + data.len() as VAddr, func);
        let last_bb = lifter.lift_cfg(data, event_pool)?;
        lifter.create_edges()?;
        lifter.ensure_continuous_flow(section_end, event_pool, last_bb)?;
        let perfect = lifter.verify()?;

        Ok(Function::new(lifter.cfg, perfect))
    }

    fn new(func_start: VAddr, func_end: VAddr, func: Option<&ListingFunction>) -> Self {
        let mut strict_mode = !cfg!(test);
        let mut bb_boundaries = HashSet::new();

        if let Some(func) = func {
            strict_mode = false;
            let mut cursor = 0;

            for offset in func.boundaries() {
                cursor += offset;
                bb_boundaries.insert(func_start + cursor as VAddr);
            }
        }

        Self {
            cfg: CFG::new(),
            bb_boundaries,
            strict_mode,
            edges: HashMap::new(),
            func_start,
            func_end,
            seen_terminator: false,
        }
    }

    fn verify(&self) -> Result<bool, AoError> {
        let perfect = self.cfg.verify()?;

        if self.strict_mode && !perfect {
            Err(AoError::CFGDisconnected)
        } else {
            Ok(perfect)
        }
    }

    fn ensure_continuous_flow(
        &mut self,
        section_end: VAddr,
        event_pool: &mut EventPool,
        last_bb: Id,
    ) -> Result<(), AoError> {
        let bb = self.cfg.basic_block(last_bb).unwrap();

        if bb.has_continuous_flow() {
            let mut has_next = false;

            for edge in bb.edges() {
                if let Edge::Next(_) = edge {
                    has_next = true;
                    break;
                }
            }

            if !has_next {
                let mut new_bb = BasicBlock::new();

                if self.func_end >= section_end {
                    new_bb.fire_event(event_pool.add_event(EVENT_BREAKPOINT));
                } else {
                    let addr = new_bb.load_virt_addr(self.func_end);
                    new_bb.jump(addr)?;
                }

                let new_id = self.cfg.add_basic_block(new_bb);

                let bb = self.cfg.basic_block_mut(last_bb).unwrap();
                bb.add_edge(Edge::Next(new_id));
            }
        }

        Ok(())
    }

    fn find_bb(&self, vaddr: VAddr) -> Option<Id> {
        for bb in self.cfg.iter_basic_blocks() {
            if bb.vaddr().unwrap() == vaddr {
                return Some(bb.id());
            }
        }

        None
    }

    fn create_edges(&mut self) -> Result<(), AoError> {
        for (from, edges) in &self.edges {
            let from = self.find_bb(*from).unwrap();

            for edge in edges {
                let addr = edge.addr();

                if let Some(to) = self.find_bb(addr) {
                    let edge = match edge {
                        UnresolvedEdge::Next(_) => Edge::Next(to),
                        UnresolvedEdge::Jump(_) => Edge::Jump(to),
                    };

                    self.cfg.basic_block_mut(from).unwrap().add_edge(edge);
                } else if *edge != UnresolvedEdge::Next(self.func_end) {
                    return Err(AoError::BasicBlockNotFound(addr));
                }
            }
        }

        Ok(())
    }

    fn insert_edge(&mut self, bb: &BasicBlock, edge: UnresolvedEdge) {
        if !self.contains_address(edge.addr()) {
            //TODO: track cross-function jumps in global set
        } else {
            self.edges.entry(bb.vaddr().unwrap()).or_default().push(edge);
        }
    }

    fn contains_address(&self, addr: VAddr) -> bool {
        self.func_start <= addr && addr < self.func_end
    }

    fn insert_boundary(&mut self, addr: VAddr) -> Result<(), AoError> {
        // Note that the end of the function is included here because we
        // want to allow jal(r)'s as the last instruction of a function
        if self.contains_address(addr) || addr == self.func_end {
            self.bb_boundaries.insert(addr);
            Ok(())
        } else {
            Err(AoError::InvalidJumpTarget(addr))
        }
    }

    fn has_edges(&self, bb: &BasicBlock) -> bool {
        if let Some(edges) = self.edges.get(&bb.vaddr().unwrap()) {
            !edges.is_empty()
        } else {
            false
        }
    }

    fn parse_boundaries(&mut self, addr: VAddr, instr: &[u8]) -> Result<(), AoError> {
        if let InstructionSet::RV32I(instr) = decode(instr) {
            match instr {
                RV32I::JAL(args) => {
                    let ret_addr = addr + 4;
                    let jump_target = addr.wrapping_add(args.imm as VAddr);

                    self.insert_boundary(ret_addr)?;

                    if self.contains_address(jump_target) {
                        let _ = self.insert_boundary(jump_target);
                    }
                },
                RV32I::JALR(_) => {
                    let ret_addr = addr + 4;
                    self.insert_boundary(ret_addr)?;
                },
                RV32I::BNE(args)
                | RV32I::BLT(args)
                | RV32I::BGE(args)
                | RV32I::BLTU(args)
                | RV32I::BGEU(args)
                | RV32I::BEQ(args) => {
                    let branch_target = addr.wrapping_add(args.imm as VAddr);

                    if self.contains_address(branch_target) {
                        let _ = self.insert_boundary(branch_target);
                    }

                    self.insert_boundary(addr + 4)?;
                },
                RV32I::ECALL(_) | RV32I::EBREAK(_) => {
                    self.insert_boundary(addr + 4)?;
                },
                _ => {},
            }
        }

        Ok(())
    }

    fn lift_cfg(&mut self, data: &[u8], event_pool: &mut EventPool) -> Result<Id, AoError> {
        /* First find out basic block boundaries with a pass over all the instructions */
        let mut i = 0;

        while i < data.len() {
            self.parse_boundaries(self.func_start + i as VAddr, &data[i..i + 4])?;
            i += 4;
        }

        self.bb_boundaries.remove(&self.func_start);

        /* Then lift instructions into IR */
        let mut i = 0;
        let mut entry = None;
        let mut bb = BasicBlock::at_vaddr(self.func_start);

        while i < data.len() {
            let addr = self.func_start + i as VAddr;

            if self.bb_boundaries.contains(&addr) {
                if !self.has_edges(&bb) && !self.seen_terminator {
                    self.insert_edge(&bb, UnresolvedEdge::Next(addr));
                }

                let id = self.cfg.add_basic_block(bb);

                if entry.is_none() {
                    entry = Some(id);
                }

                bb = BasicBlock::at_vaddr(addr);
            }

            self.lift_instruction(addr, &data[i..i + 4], event_pool, &mut bb)?;
            i += 4;
        }

        let id = self.cfg.add_basic_block(bb);
        self.cfg.set_entry(entry.unwrap_or(id));

        Ok(id)
    }

    fn lift_instruction(
        &mut self,
        addr: VAddr,
        instr: &[u8],
        event_pool: &mut EventPool,
        bb: &mut BasicBlock,
    ) -> Result<(), AoError> {
        bb.next_instruction(addr);

        self.seen_terminator = false;

        match decode(instr) {
            InstructionSet::RV32I(instr) => match instr {
                RV32I::LUI(args) => {
                    let var = bb.load_immediate(args.imm as u64);
                    bb.store_gp_register(GpRegister::from_usize(args.rd), var)?;
                },
                RV32I::AUIPC(args) => {
                    let vaddr = addr.wrapping_add(args.imm as VAddr);
                    let var = bb.load_virt_addr(vaddr);
                    bb.store_gp_register(GpRegister::from_usize(args.rd), var)?;
                },
                RV32I::JAL(args) => {
                    let ret_addr = addr + 4;
                    let var = bb.load_virt_addr(ret_addr);
                    bb.store_gp_register(GpRegister::from_usize(args.rd), var)?;

                    let jump_target = addr.wrapping_add(args.imm as VAddr);
                    let var = bb.load_virt_addr(jump_target);
                    bb.jump(var)?;

                    if args.rd != GpRegister::zero as usize {
                        self.insert_edge(bb, UnresolvedEdge::Next(ret_addr));
                    }
                    if self.contains_address(jump_target) {
                        self.insert_edge(bb, UnresolvedEdge::Jump(jump_target));
                    }

                    self.seen_terminator = true;
                },
                RV32I::JALR(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let jump_target = bb.add(rs1, imm, ArithmeticBehavior::default())?;

                    let ret_addr = addr + 4;
                    let var = bb.load_virt_addr(ret_addr);
                    bb.store_gp_register(GpRegister::from_usize(args.rd), var)?;

                    bb.jump(jump_target)?;

                    if args.rd != GpRegister::zero as usize {
                        self.insert_edge(bb, UnresolvedEdge::Next(ret_addr));
                    }

                    self.seen_terminator = true;
                },
                RV32I::BEQ(args) => {
                    let l = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let r = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.compare(l, r, Comparison::Equal)?;

                    let branch_target = addr.wrapping_add(args.imm as VAddr);
                    let var = bb.load_virt_addr(branch_target);
                    bb.branch(var, result)?;

                    self.insert_edge(bb, UnresolvedEdge::Jump(branch_target));
                    self.insert_edge(bb, UnresolvedEdge::Next(addr + 4));

                    self.seen_terminator = true;
                },
                RV32I::BNE(args) => {
                    let lhs = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rhs = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.compare(lhs, rhs, Comparison::NotEqual)?;

                    let branch_target = addr.wrapping_add(args.imm as VAddr);
                    let dst = bb.load_virt_addr(branch_target);
                    bb.branch(dst, result)?;

                    self.insert_edge(bb, UnresolvedEdge::Jump(branch_target));
                    self.insert_edge(bb, UnresolvedEdge::Next(addr + 4));

                    self.seen_terminator = true;
                },
                RV32I::BLT(args) => {
                    let lhs = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rhs = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.compare(lhs, rhs, Comparison::Less(true))?;

                    let branch_target = addr.wrapping_add(args.imm as VAddr);
                    let dst = bb.load_virt_addr(branch_target);
                    bb.branch(dst, result)?;

                    self.insert_edge(bb, UnresolvedEdge::Jump(branch_target));
                    self.insert_edge(bb, UnresolvedEdge::Next(addr + 4));

                    self.seen_terminator = true;
                },
                RV32I::BGE(args) => {
                    let lhs = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rhs = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.compare(rhs, lhs, Comparison::LessEqual(true))?;

                    let branch_target = addr.wrapping_add(args.imm as VAddr);
                    let dst = bb.load_virt_addr(branch_target);
                    bb.branch(dst, result)?;

                    self.insert_edge(bb, UnresolvedEdge::Jump(branch_target));
                    self.insert_edge(bb, UnresolvedEdge::Next(addr + 4));

                    self.seen_terminator = true;
                },
                RV32I::BLTU(args) => {
                    let lhs = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rhs = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.compare(lhs, rhs, Comparison::Less(false))?;

                    let branch_target = addr.wrapping_add(args.imm as VAddr);
                    let dst = bb.load_virt_addr(branch_target);
                    bb.branch(dst, result)?;

                    self.insert_edge(bb, UnresolvedEdge::Jump(branch_target));
                    self.insert_edge(bb, UnresolvedEdge::Next(addr + 4));

                    self.seen_terminator = true;
                },
                RV32I::BGEU(args) => {
                    let lhs = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rhs = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.compare(rhs, lhs, Comparison::LessEqual(false))?;

                    let branch_target = addr.wrapping_add(args.imm as VAddr);
                    let dst = bb.load_virt_addr(branch_target);
                    bb.branch(dst, result)?;

                    self.insert_edge(bb, UnresolvedEdge::Jump(branch_target));
                    self.insert_edge(bb, UnresolvedEdge::Next(addr + 4));

                    self.seen_terminator = true;
                },
                RV32I::LB(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let addr = bb.add(rs1, imm, ArithmeticBehavior::default())?;
                    let byte = bb.load_byte(addr)?;
                    let result = bb.sign_extend(byte, 1)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32I::LH(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let addr = bb.add(rs1, imm, ArithmeticBehavior::default())?;
                    let hword = bb.load_hword(addr)?;
                    let result = bb.sign_extend(hword, 2)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32I::LW(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let addr = bb.add(rs1, imm, ArithmeticBehavior::default())?;
                    let word = bb.load_word(addr)?;
                    let result = bb.sign_extend(word, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32I::LBU(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let addr = bb.add(rs1, imm, ArithmeticBehavior::default())?;
                    let byte = bb.load_byte(addr)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), byte)?;
                },
                RV32I::LHU(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let addr = bb.add(rs1, imm, ArithmeticBehavior::default())?;
                    let hword = bb.load_hword(addr)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), hword)?;
                },
                RV32I::SB(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let addr = bb.add(rs1, imm, ArithmeticBehavior::default())?;
                    let value = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    bb.store_byte(addr, value)?;
                },
                RV32I::SH(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let addr = bb.add(rs1, imm, ArithmeticBehavior::default())?;
                    let value = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    bb.store_hword(addr, value)?;
                },
                RV32I::SW(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let addr = bb.add(rs1, imm, ArithmeticBehavior::default())?;
                    let value = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    bb.store_word(addr, value)?;
                },
                RV32I::ADDI(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let result = bb.add(rs1, imm, ArithmeticBehavior::default())?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32I::SLTI(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let result = bb.compare(rs1, imm, Comparison::Less(true))?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32I::SLTIU(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let result = bb.compare(rs1, imm, Comparison::Less(false))?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32I::XORI(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let result = bb.xor(rs1, imm)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32I::ORI(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let result = bb.or(rs1, imm)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32I::ANDI(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let result = bb.and(rs1, imm)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                //RV32I::SLLI(_) => unimplemented!(),
                //RV32I::SRLI(_) => unimplemented!(),
                //RV32I::SRAI(_) => unimplemented!(),
                RV32I::ADD(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.add(rs1, rs2, ArithmeticBehavior::default())?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32I::SUB(args) => {
                    let lhs = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rhs = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.sub(lhs, rhs)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32I::SLL(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.shift_left(rs1, rs2)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32I::SLT(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.compare(rs1, rs2, Comparison::Less(true))?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32I::SLTU(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.compare(rs1, rs2, Comparison::Less(false))?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32I::XOR(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.xor(rs1, rs2)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32I::SRL(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.shift_right_logical(rs1, rs2)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32I::SRA(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.shift_right_arithmetic(rs1, rs2)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32I::OR(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.or(rs1, rs2)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32I::AND(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.and(rs1, rs2)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32I::FENCE(_) => {
                    bb.nop();
                },
                RV32I::ECALL(_) => {
                    bb.fire_event(event_pool.add_event(EVENT_SYSCALL));
                    self.insert_edge(bb, UnresolvedEdge::Next(addr + 4));
                    self.seen_terminator = true;
                },
                RV32I::EBREAK(_) => {
                    bb.fire_event(event_pool.add_event(EVENT_BREAKPOINT));
                    // We allow instructions after an ebreak but the dead-code-elimination pass will remove them
                    self.insert_edge(bb, UnresolvedEdge::Next(addr + 4));
                    self.seen_terminator = true;
                },
            },
            InstructionSet::RV64I(instr) => match instr {
                RV64I::LWU(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let addr = bb.add(rs1, imm, ArithmeticBehavior::default())?;
                    let result = bb.load_word(addr)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64I::LD(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let addr = bb.add(rs1, imm, ArithmeticBehavior::default())?;
                    let result = bb.load_dword(addr)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64I::SD(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let addr = bb.add(rs1, imm, ArithmeticBehavior::default())?;
                    let value = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    bb.store_dword(addr, value)?;
                },
                RV64I::SLLI(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let result = bb.shift_left(rs1, imm)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64I::SRLI(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let result = bb.shift_right_logical(rs1, imm)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64I::SRAI(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let result = bb.shift_right_arithmetic(rs1, imm)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64I::ADDIW(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let sum = bb.add(rs1, imm, ArithmeticBehavior::default())?;
                    let result = bb.sign_extend(sum, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64I::SLLIW(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let mask = bb.load_immediate(0b11111);
                    let value = bb.zero_extend(rs1, 4)?;
                    let amount = bb.and(imm, mask)?;
                    let result = bb.shift_left(value, amount)?;
                    let result = bb.sign_extend(result, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64I::SRLIW(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let mask = bb.load_immediate(0b11111);
                    let value = bb.zero_extend(rs1, 4)?;
                    let amount = bb.and(imm, mask)?;
                    let result = bb.shift_right_logical(value, amount)?;
                    let result = bb.sign_extend(result, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64I::SRAIW(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let mask = bb.load_immediate(0b11111);
                    let rs1 = bb.sign_extend(rs1, 4)?;
                    let amount = bb.and(imm, mask)?;
                    let result = bb.shift_right_arithmetic(rs1, amount)?;
                    let result = bb.sign_extend(result, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64I::ADDW(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let rs1 = bb.zero_extend(rs1, 4)?;
                    let rs2 = bb.zero_extend(rs2, 4)?;
                    let result = bb.add(rs1, rs2, ArithmeticBehavior::default())?;
                    let result = bb.sign_extend(result, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64I::SUBW(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let rs1 = bb.sign_extend(rs1, 4)?;
                    let rs2 = bb.sign_extend(rs2, 4)?;
                    let result = bb.sub(rs1, rs2)?;
                    let result = bb.sign_extend(result, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64I::SLLW(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let mask = bb.load_immediate(0b11111);
                    let rs1 = bb.zero_extend(rs1, 4)?;
                    let amount = bb.and(rs2, mask)?;
                    let result = bb.shift_left(rs1, amount)?;
                    let result = bb.sign_extend(result, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64I::SRLW(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let mask = bb.load_immediate(0b11111);
                    let rs1 = bb.zero_extend(rs1, 4)?;
                    let rs2 = bb.and(rs2, mask)?;
                    let result = bb.shift_right_logical(rs1, rs2)?;
                    let result = bb.sign_extend(result, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64I::SRAW(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let mask = bb.load_immediate(0b11111);
                    let rs1 = bb.sign_extend(rs1, 4)?;
                    let amount = bb.and(rs2, mask)?;
                    let result = bb.shift_right_arithmetic(rs1, amount)?;
                    let result = bb.sign_extend(result, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
            },
            InstructionSet::RV32A(instr) => match instr {
                RV32A::LR(args) => {
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let value = bb.load_word(address)?;
                    let value = bb.sign_extend(value, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), value)?;
                },
                RV32A::SC(args) => {
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    bb.store_word(address, rs2)?;
                    let zero = bb.load_immediate(0);
                    bb.store_gp_register(GpRegister::from_usize(args.rd), zero)?;
                },
                RV32A::AMOSWAP(args) => {
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let rs2 = bb.zero_extend(rs2, 4)?;
                    let word = bb.load_word(address)?;
                    let dword = bb.sign_extend(word, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), dword)?;
                    bb.store_word(address, rs2)?;
                },
                RV32A::AMOADD(args) => {
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let rs2 = bb.zero_extend(rs2, 4)?;
                    let word = bb.load_word(address)?;
                    let dword = bb.sign_extend(word, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), dword)?;
                    let result = bb.add(rs2, word, ArithmeticBehavior::default())?;
                    bb.store_word(address, result)?;
                },
                RV32A::AMOXOR(args) => {
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let rs2 = bb.zero_extend(rs2, 4)?;
                    let word = bb.load_word(address)?;
                    let dword = bb.sign_extend(word, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), dword)?;
                    let result = bb.xor(rs2, word)?;
                    bb.store_word(address, result)?;
                },
                RV32A::AMOAND(args) => {
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let rs2 = bb.zero_extend(rs2, 4)?;
                    let word = bb.load_word(address)?;
                    let dword = bb.sign_extend(word, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), dword)?;
                    let result = bb.and(rs2, word)?;
                    bb.store_word(address, result)?;
                },
                RV32A::AMOOR(args) => {
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let rs2 = bb.zero_extend(rs2, 4)?;
                    let word = bb.load_word(address)?;
                    let dword = bb.sign_extend(word, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), dword)?;
                    let result = bb.or(rs2, word)?;
                    bb.store_word(address, result)?;
                },
                RV32A::AMOMIN(args) => {
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let rs2 = bb.sign_extend(rs2, 4)?;
                    let word = bb.load_word(address)?;
                    let dword = bb.sign_extend(word, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), dword)?;
                    let result = bb.minimum_number(rs2, dword, Signedness::Signed)?;
                    bb.store_word(address, result)?;
                },
                RV32A::AMOMAX(args) => {
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let rs2 = bb.sign_extend(rs2, 4)?;
                    let word = bb.load_word(address)?;
                    let dword = bb.sign_extend(word, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), dword)?;
                    let result = bb.maximum_number(rs2, dword, Signedness::Signed)?;
                    bb.store_word(address, result)?;
                },
                RV32A::AMOMINU(args) => {
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let rs2 = bb.zero_extend(rs2, 4)?;
                    let word = bb.load_word(address)?;
                    let dword = bb.sign_extend(word, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), dword)?;
                    let result = bb.minimum_number(rs2, word, Signedness::Unsigned)?;
                    bb.store_word(address, result)?;
                },
                RV32A::AMOMAXU(args) => {
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let rs2 = bb.zero_extend(rs2, 4)?;
                    let word = bb.load_word(address)?;
                    let dword = bb.sign_extend(word, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), dword)?;
                    let result = bb.maximum_number(rs2, word, Signedness::Unsigned)?;
                    bb.store_word(address, result)?;
                },
            },
            InstructionSet::RV64A(instr) => match instr {
                RV64A::LR(args) => {
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let value = bb.load_dword(address)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), value)?;
                },
                RV64A::SC(args) => {
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    bb.store_dword(address, rs2)?;
                    let zero = bb.load_immediate(0);
                    bb.store_gp_register(GpRegister::from_usize(args.rd), zero)?;
                },
                RV64A::AMOSWAP(args) => {
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let dword = bb.load_dword(address)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), dword)?;
                    bb.store_dword(address, rs2)?;
                },
                RV64A::AMOADD(args) => {
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let dword = bb.load_dword(address)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), dword)?;
                    let result = bb.add(dword, rs2, ArithmeticBehavior::default())?;
                    bb.store_dword(address, result)?;
                },
                RV64A::AMOXOR(args) => {
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let dword = bb.load_dword(address)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), dword)?;
                    let result = bb.xor(dword, rs2)?;
                    bb.store_dword(address, result)?;
                },
                RV64A::AMOAND(args) => {
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let dword = bb.load_dword(address)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), dword)?;
                    let result = bb.and(dword, rs2)?;
                    bb.store_dword(address, result)?;
                },
                RV64A::AMOOR(args) => {
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let dword = bb.load_dword(address)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), dword)?;
                    let result = bb.or(dword, rs2)?;
                    bb.store_dword(address, result)?;
                },
                RV64A::AMOMIN(args) => {
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let dword = bb.load_dword(address)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), dword)?;
                    let result = bb.minimum_number(dword, rs2, Signedness::Signed)?;
                    bb.store_dword(address, result)?;
                },
                RV64A::AMOMAX(args) => {
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let dword = bb.load_dword(address)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), dword)?;
                    let result = bb.maximum_number(dword, rs2, Signedness::Signed)?;
                    bb.store_dword(address, result)?;
                },
                RV64A::AMOMINU(args) => {
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let dword = bb.load_dword(address)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), dword)?;
                    let result = bb.minimum_number(dword, rs2, Signedness::Unsigned)?;
                    bb.store_dword(address, result)?;
                },
                RV64A::AMOMAXU(args) => {
                    let address = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let dword = bb.load_dword(address)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), dword)?;
                    let result = bb.maximum_number(dword, rs2, Signedness::Unsigned)?;
                    bb.store_dword(address, result)?;
                },
            },
            InstructionSet::RV32F(instr) => match instr {
                RV32F::FLW(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let addr = bb.add(rs1, imm, ArithmeticBehavior::default())?;
                    let float = bb.load_float32(addr)?;
                    let double = bb.nan_box(float)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), double)?;
                },
                RV32F::FSW(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let addr = bb.add(rs1, imm, ArithmeticBehavior::default())?;
                    let double = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let float = bb.reinterpret_as_float32(double);
                    bb.store_float32(addr, float)?;
                },
                RV32F::FMADD(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.nan_unbox(rs2)?;
                    let rs3 = bb.load_fp_register(FpRegister::from_usize(args.rs3));
                    let rs3 = bb.nan_unbox(rs3)?;
                    let result = bb.multiply_add(rs1, rs2, rs3)?;
                    let result = bb.convert_nan(result)?;
                    let result = bb.nan_box(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FMSUB(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.nan_unbox(rs2)?;
                    let rs3 = bb.load_fp_register(FpRegister::from_usize(args.rs3));
                    let rs3 = bb.nan_unbox(rs3)?;
                    let rs3 = bb.negate(rs3);
                    let result = bb.multiply_add(rs1, rs2, rs3)?;
                    let result = bb.convert_nan(result)?;
                    let result = bb.nan_box(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FNMSUB(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.nan_unbox(rs2)?;
                    let rs2 = bb.negate(rs2);
                    let rs3 = bb.load_fp_register(FpRegister::from_usize(args.rs3));
                    let rs3 = bb.nan_unbox(rs3)?;
                    let result = bb.multiply_add(rs1, rs2, rs3)?;
                    let result = bb.convert_nan(result)?;
                    let result = bb.nan_box(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FNMADD(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.nan_unbox(rs2)?;
                    let rs2 = bb.negate(rs2);
                    let rs3 = bb.load_fp_register(FpRegister::from_usize(args.rs3));
                    let rs3 = bb.nan_unbox(rs3)?;
                    let rs3 = bb.negate(rs3);
                    let result = bb.multiply_add(rs1, rs2, rs3)?;
                    let result = bb.convert_nan(result)?;
                    let result = bb.nan_box(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FADD(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.nan_unbox(rs2)?;
                    let result = bb.add(rs1, rs2, ArithmeticBehavior::default())?;
                    let result = bb.convert_nan(result)?;
                    let result = bb.nan_box(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FSUB(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.nan_unbox(rs2)?;
                    let result = bb.sub(rs1, rs2)?;
                    let result = bb.convert_nan(result)?;
                    let result = bb.nan_box(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FMUL(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.nan_unbox(rs2)?;
                    let result = bb.multiply_float(rs1, rs2)?;
                    let result = bb.convert_nan(result)?;
                    let result = bb.nan_box(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FDIV(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.nan_unbox(rs2)?;
                    let result = bb.divide_float(rs1, rs2)?;
                    let result = bb.convert_nan(result)?;
                    let result = bb.nan_box(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FSQRT(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let result = bb.sqrt(rs1)?;
                    let result = bb.convert_nan(result)?;
                    let result = bb.nan_box(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FSGNJ(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let rs1 = bb.reinterpret_as_number(rs1)?;
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.nan_unbox(rs2)?;
                    let rs2 = bb.reinterpret_as_number(rs2)?;
                    let sign_bit = 1u64 << 31;
                    let del_sign_mask = bb.load_immediate(!sign_bit);
                    let ext_sign_mask = bb.load_immediate(sign_bit);
                    let base = bb.and(rs1, del_sign_mask)?;
                    let sign_bit = bb.and(rs2, ext_sign_mask)?;
                    let result = bb.or(base, sign_bit)?;
                    let result = bb.reinterpret_as_float32(result);
                    let result = bb.nan_box(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FSGNJN(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let rs1 = bb.reinterpret_as_number(rs1)?;
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.nan_unbox(rs2)?;
                    let rs2 = bb.reinterpret_as_number(rs2)?;
                    let rs2 = bb.invert(rs2)?;
                    let sign_bit = 1u64 << 31;
                    let del_sign_mask = bb.load_immediate(!sign_bit);
                    let ext_sign_mask = bb.load_immediate(sign_bit);
                    let base = bb.and(rs1, del_sign_mask)?;
                    let sign_bit = bb.and(rs2, ext_sign_mask)?;
                    let result = bb.or(base, sign_bit)?;
                    let result = bb.reinterpret_as_float32(result);
                    let result = bb.nan_box(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FSGNJX(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let rs1 = bb.reinterpret_as_number(rs1)?;
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.nan_unbox(rs2)?;
                    let rs2 = bb.reinterpret_as_number(rs2)?;
                    let sign_bit = 1u64 << 31;
                    let del_sign_mask = bb.load_immediate(!sign_bit);
                    let ext_sign_mask = bb.load_immediate(sign_bit);
                    let rs1_sign = bb.and(rs1, ext_sign_mask)?;
                    let rs2_sign = bb.and(rs2, ext_sign_mask)?;
                    let sign_bit = bb.xor(rs1_sign, rs2_sign)?;
                    let base = bb.and(rs1, del_sign_mask)?;
                    let result = bb.or(base, sign_bit)?;
                    let result = bb.reinterpret_as_float32(result);
                    let result = bb.nan_box(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FMIN(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.nan_unbox(rs2)?;
                    let result = bb.minimum_float(rs1, rs2)?;
                    let result = bb.nan_box(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FMAX(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.nan_unbox(rs2)?;
                    let result = bb.maximum_float(rs1, rs2)?;
                    let result = bb.nan_box(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FEQ(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.nan_unbox(rs2)?;
                    let result = bb.compare(rs1, rs2, Comparison::Equal)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FLT(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.nan_unbox(rs2)?;
                    let result = bb.compare(rs1, rs2, Comparison::Less(false))?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FLE(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.nan_unbox(rs2)?;
                    let result = bb.compare(rs1, rs2, Comparison::LessEqual(false))?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FCLASS(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let result = bb.classify(rs1)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FMV_XW(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.reinterpret_as_number(rs1)?;
                    let rs1 = bb.sign_extend(rs1, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), rs1)?;
                },
                RV32F::FMV_WX(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs1 = bb.reinterpret_as_float32(rs1);
                    let rs1 = bb.nan_box(rs1)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), rs1)?;
                },
                RV32F::FCVT_WS(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let rm = if args.funct3 == rm::DYNAMIC {
                        bb.load_csr(CsrRegister::frm)?
                    } else {
                        bb.load_immediate(args.funct3)
                    };
                    let result = bb.round(rs1, rm)?;
                    let result = bb.convert_to_integer32(result, Signedness::Signed);
                    let result = bb.sign_extend(result, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FCVT_WUS(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let rm = if args.funct3 == rm::DYNAMIC {
                        bb.load_csr(CsrRegister::frm)?
                    } else {
                        bb.load_immediate(args.funct3)
                    };
                    let result = bb.round(rs1, rm)?;
                    let result = bb.convert_to_integer32(result, Signedness::Unsigned);
                    let result = bb.sign_extend(result, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FCVT_SW(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs1 = bb.sign_extend(rs1, 4)?;
                    let result = bb.convert_to_float32(rs1, Signedness::Signed);
                    let result = bb.nan_box(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32F::FCVT_SWU(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs1 = bb.zero_extend(rs1, 4)?;
                    let result = bb.convert_to_float32(rs1, Signedness::Unsigned);
                    let result = bb.nan_box(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
            },
            InstructionSet::RV64F(instr) => match instr {
                RV64F::FCVT_LS(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let rm = if args.funct3 == rm::DYNAMIC {
                        bb.load_csr(CsrRegister::frm)?
                    } else {
                        bb.load_immediate(args.funct3)
                    };
                    let result = bb.round(rs1, rm)?;
                    let result = bb.convert_to_integer64(result, Signedness::Signed);
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64F::FCVT_LUS(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let rm = if args.funct3 == rm::DYNAMIC {
                        bb.load_csr(CsrRegister::frm)?
                    } else {
                        bb.load_immediate(args.funct3)
                    };
                    let result = bb.round(rs1, rm)?;
                    let result = bb.convert_to_integer64(result, Signedness::Unsigned);
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64F::FCVT_SL(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let result = bb.convert_to_float32(rs1, Signedness::Signed);
                    let result = bb.nan_box(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV64F::FCVT_SLU(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let result = bb.convert_to_float32(rs1, Signedness::Unsigned);
                    let result = bb.nan_box(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
            },
            InstructionSet::RV32D(instr) => match instr {
                RV32D::FLD(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let addr = bb.add(rs1, imm, ArithmeticBehavior::default())?;
                    let double = bb.load_float64(addr)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), double)?;
                },
                RV32D::FSD(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let imm = bb.load_immediate(args.imm as u64);
                    let addr = bb.add(rs1, imm, ArithmeticBehavior::default())?;
                    let double = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    bb.store_float64(addr, double)?;
                },
                RV32D::FMADD(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs3 = bb.load_fp_register(FpRegister::from_usize(args.rs3));
                    let result = bb.multiply_add(rs1, rs2, rs3)?;
                    let result = bb.convert_nan(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FMSUB(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs3 = bb.load_fp_register(FpRegister::from_usize(args.rs3));
                    let rs3 = bb.negate(rs3);
                    let result = bb.multiply_add(rs1, rs2, rs3)?;
                    let result = bb.convert_nan(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FNMSUB(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.negate(rs2);
                    let rs3 = bb.load_fp_register(FpRegister::from_usize(args.rs3));
                    let result = bb.multiply_add(rs1, rs2, rs3)?;
                    let result = bb.convert_nan(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FNMADD(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.negate(rs2);
                    let rs3 = bb.load_fp_register(FpRegister::from_usize(args.rs3));
                    let rs3 = bb.negate(rs3);
                    let result = bb.multiply_add(rs1, rs2, rs3)?;
                    let result = bb.convert_nan(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FADD(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let result = bb.add(rs1, rs2, ArithmeticBehavior::default())?;
                    let result = bb.convert_nan(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FSUB(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let result = bb.sub(rs1, rs2)?;
                    let result = bb.convert_nan(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FMUL(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let result = bb.multiply_float(rs1, rs2)?;
                    let result = bb.convert_nan(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FDIV(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let result = bb.divide_float(rs1, rs2)?;
                    let result = bb.convert_nan(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FSQRT(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let result = bb.sqrt(rs1)?;
                    let result = bb.convert_nan(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FSGNJ(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.reinterpret_as_number(rs1)?;
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.reinterpret_as_number(rs2)?;
                    let sign_bit = 1u64 << 63;
                    let del_sign_mask = bb.load_immediate(!sign_bit);
                    let ext_sign_mask = bb.load_immediate(sign_bit);
                    let base = bb.and(rs1, del_sign_mask)?;
                    let sign_bit = bb.and(rs2, ext_sign_mask)?;
                    let result = bb.or(base, sign_bit)?;
                    let result = bb.reinterpret_as_float64(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FSGNJN(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.reinterpret_as_number(rs1)?;
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.reinterpret_as_number(rs2)?;
                    let rs2 = bb.invert(rs2)?;
                    let sign_bit = 1u64 << 63;
                    let del_sign_mask = bb.load_immediate(!sign_bit);
                    let ext_sign_mask = bb.load_immediate(sign_bit);
                    let base = bb.and(rs1, del_sign_mask)?;
                    let sign_bit = bb.and(rs2, ext_sign_mask)?;
                    let result = bb.or(base, sign_bit)?;
                    let result = bb.reinterpret_as_float64(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FSGNJX(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.reinterpret_as_number(rs1)?;
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let rs2 = bb.reinterpret_as_number(rs2)?;
                    let sign_bit = 1u64 << 63;
                    let del_sign_mask = bb.load_immediate(!sign_bit);
                    let ext_sign_mask = bb.load_immediate(sign_bit);
                    let rs1_sign = bb.and(rs1, ext_sign_mask)?;
                    let rs2_sign = bb.and(rs2, ext_sign_mask)?;
                    let sign_bit = bb.xor(rs1_sign, rs2_sign)?;
                    let base = bb.and(rs1, del_sign_mask)?;
                    let result = bb.or(base, sign_bit)?;
                    let result = bb.reinterpret_as_float64(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FMIN(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let result = bb.minimum_float(rs1, rs2)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FMAX(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let result = bb.maximum_float(rs1, rs2)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FEQ(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let result = bb.compare(rs1, rs2, Comparison::Equal)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FLT(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let result = bb.compare(rs1, rs2, Comparison::Less(false))?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FLE(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_fp_register(FpRegister::from_usize(args.rs2));
                    let result = bb.compare(rs1, rs2, Comparison::LessEqual(false))?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FCLASS(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let result = bb.classify(rs1)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FCVT_SD(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let result = bb.convert_to_float32(rs1, Signedness::Signed);
                    let result = bb.convert_nan(result)?;
                    let result = bb.nan_box(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FCVT_DS(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.nan_unbox(rs1)?;
                    let result = bb.convert_to_float64(rs1, Signedness::Signed);
                    let result = bb.convert_nan(result)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FCVT_WD(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rm = if args.funct3 == rm::DYNAMIC {
                        bb.load_csr(CsrRegister::frm)?
                    } else {
                        bb.load_immediate(args.funct3)
                    };
                    let result = bb.round(rs1, rm)?;
                    let result = bb.convert_to_integer32(result, Signedness::Signed);
                    let result = bb.sign_extend(result, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FCVT_WUD(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rm = if args.funct3 == rm::DYNAMIC {
                        bb.load_csr(CsrRegister::frm)?
                    } else {
                        bb.load_immediate(args.funct3)
                    };
                    let result = bb.round(rs1, rm)?;
                    let result = bb.convert_to_integer32(result, Signedness::Unsigned);
                    let result = bb.sign_extend(result, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FCVT_DW(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs1 = bb.sign_extend(rs1, 4)?;
                    let result = bb.convert_to_float64(rs1, Signedness::Signed);
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV32D::FCVT_DWU(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs1 = bb.zero_extend(rs1, 4)?;
                    let result = bb.convert_to_float64(rs1, Signedness::Unsigned);
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
            },
            InstructionSet::RV64D(instr) => match instr {
                RV64D::FCVT_LD(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rm = if args.funct3 == rm::DYNAMIC {
                        bb.load_csr(CsrRegister::frm)?
                    } else {
                        bb.load_immediate(args.funct3)
                    };
                    let result = bb.round(rs1, rm)?;
                    let result = bb.convert_to_integer64(result, Signedness::Signed);
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64D::FCVT_LUD(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rm = if args.funct3 == rm::DYNAMIC {
                        bb.load_csr(CsrRegister::frm)?
                    } else {
                        bb.load_immediate(args.funct3)
                    };
                    let result = bb.round(rs1, rm)?;
                    let result = bb.convert_to_integer64(result, Signedness::Unsigned);
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64D::FCVT_DL(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let result = bb.convert_to_float64(rs1, Signedness::Signed);
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV64D::FCVT_DLU(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let result = bb.convert_to_float64(rs1, Signedness::Unsigned);
                    bb.store_fp_register(FpRegister::from_usize(args.rd), result)?;
                },
                RV64D::FMV_XD(args) => {
                    let rs1 = bb.load_fp_register(FpRegister::from_usize(args.rs1));
                    let rs1 = bb.reinterpret_as_number(rs1)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), rs1)?;
                },
                RV64D::FMV_DX(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs1 = bb.reinterpret_as_float64(rs1)?;
                    bb.store_fp_register(FpRegister::from_usize(args.rd), rs1)?;
                },
            },
            InstructionSet::CSR(instr) => match instr {
                CSR::RW(args) => {
                    let csr = (args.imm & 0xFFF) as usize;
                    let new_value = bb.load_gp_register(GpRegister::from_usize(args.rs1));

                    if args.rd != GpRegister::zero as usize {
                        let old_value = bb.load_csr(CsrRegister::from_usize(csr))?;
                        bb.store_gp_register(GpRegister::from_usize(args.rd), old_value)?;
                    }

                    bb.store_csr(CsrRegister::from_usize(csr), new_value)?;
                },
                CSR::RS(args) => {
                    let csr = (args.imm & 0xFFF) as usize;
                    let old_value = bb.load_csr(CsrRegister::from_usize(csr))?;

                    if args.rs1 != GpRegister::zero as usize {
                        let mask = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                        let new_value = bb.or(old_value, mask)?;
                        bb.store_csr(CsrRegister::from_usize(csr), new_value)?;
                    }

                    bb.store_gp_register(GpRegister::from_usize(args.rd), old_value)?;
                },
                CSR::RC(args) => {
                    let csr = (args.imm & 0xFFF) as usize;
                    let old_value = bb.load_csr(CsrRegister::from_usize(csr))?;

                    if args.rs1 != GpRegister::zero as usize {
                        let mask = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                        let mask = bb.invert(mask)?;
                        let new_value = bb.and(old_value, mask)?;
                        bb.store_csr(CsrRegister::from_usize(csr), new_value)?;
                    }

                    bb.store_gp_register(GpRegister::from_usize(args.rd), old_value)?;
                },
                CSR::RWI(args) => {
                    let csr = (args.imm & 0xFFF) as usize;
                    let new_value = bb.load_immediate(args.rs1 as u64);

                    if args.rd != GpRegister::zero as usize {
                        let old_value = bb.load_csr(CsrRegister::from_usize(csr))?;
                        bb.store_gp_register(GpRegister::from_usize(args.rd), old_value)?;
                    }

                    bb.store_csr(CsrRegister::from_usize(csr), new_value)?;
                },
                CSR::RSI(args) => {
                    let csr = (args.imm & 0xFFF) as usize;
                    let old_value = bb.load_csr(CsrRegister::from_usize(csr))?;

                    if args.rs1 != 0 {
                        let mask = bb.load_immediate(args.rs1 as u64);
                        let new_value = bb.or(old_value, mask)?;
                        bb.store_csr(CsrRegister::from_usize(csr), new_value)?;
                    }

                    bb.store_gp_register(GpRegister::from_usize(args.rd), old_value)?;
                },
                CSR::RCI(args) => {
                    let csr = (args.imm & 0xFFF) as usize;
                    let old_value = bb.load_csr(CsrRegister::from_usize(csr))?;

                    if args.rs1 != 0 {
                        let mask = bb.load_immediate(args.rs1 as u64);
                        let mask = bb.invert(mask)?;
                        let new_value = bb.and(old_value, mask)?;
                        bb.store_csr(CsrRegister::from_usize(csr), new_value)?;
                    }

                    bb.store_gp_register(GpRegister::from_usize(args.rd), old_value)?;
                },
            },
            InstructionSet::RV32M(instr) => match instr {
                RV32M::MUL(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.multiply_number(rs1, rs2, Half::Lower, Signedness::Signed)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32M::MULH(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.multiply_number(rs1, rs2, Half::Upper, Signedness::Signed)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32M::MULHSU(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.multiply_number(rs1, rs2, Half::Upper, Signedness::Mixed)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32M::MULHU(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.multiply_number(rs1, rs2, Half::Upper, Signedness::Unsigned)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32M::DIV(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.divide_number(rs1, rs2, Signedness::Signed)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32M::DIVU(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.divide_number(rs1, rs2, Signedness::Unsigned)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32M::REM(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.remainder_number(rs1, rs2, Signedness::Signed)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV32M::REMU(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let result = bb.remainder_number(rs1, rs2, Signedness::Unsigned)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
            },
            InstructionSet::RV64M(instr) => match instr {
                RV64M::MULW(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs1 = bb.sign_extend(rs1, 4)?;
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let rs2 = bb.sign_extend(rs2, 4)?;
                    let result = bb.multiply_number(rs1, rs2, Half::Lower, Signedness::Signed)?;
                    let result = bb.sign_extend(result, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64M::DIVW(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs1 = bb.sign_extend(rs1, 4)?;
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let rs2 = bb.sign_extend(rs2, 4)?;
                    let result = bb.divide_number(rs1, rs2, Signedness::Signed)?;
                    let result = bb.sign_extend(result, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64M::DIVUW(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs1 = bb.zero_extend(rs1, 4)?;
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let rs2 = bb.zero_extend(rs2, 4)?;
                    let result = bb.divide_number(rs1, rs2, Signedness::Unsigned)?;
                    let result = bb.sign_extend(result, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64M::REMW(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs1 = bb.sign_extend(rs1, 4)?;
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let rs2 = bb.sign_extend(rs2, 4)?;
                    let result = bb.remainder_number(rs1, rs2, Signedness::Signed)?;
                    let result = bb.sign_extend(result, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
                RV64M::REMUW(args) => {
                    let rs1 = bb.load_gp_register(GpRegister::from_usize(args.rs1));
                    let rs1 = bb.zero_extend(rs1, 4)?;
                    let rs2 = bb.load_gp_register(GpRegister::from_usize(args.rs2));
                    let rs2 = bb.zero_extend(rs2, 4)?;
                    let result = bb.remainder_number(rs1, rs2, Signedness::Unsigned)?;
                    let result = bb.sign_extend(result, 4)?;
                    bb.store_gp_register(GpRegister::from_usize(args.rd), result)?;
                },
            },
            InstructionSet::Unknown(instr) => return Err(AoError::UnknownInstr(instr)),
        }

        Ok(())
    }
}
