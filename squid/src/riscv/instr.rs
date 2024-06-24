#![allow(clippy::upper_case_acronyms)]
#![allow(non_camel_case_types)]

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct TypeU {
    pub(crate) rd: usize,
    pub(crate) imm: i64,
}
impl TypeU {
    pub(crate) fn decode(instruction: u32) -> TypeU {
        TypeU {
            rd: ((instruction >> 7) & 0b11111) as usize,
            imm: (instruction & 0xFFFFF000) as i32 as i64,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct TypeJ {
    pub(crate) rd: usize,
    pub(crate) imm: i64,
}
impl TypeJ {
    pub(crate) fn decode(instruction: u32) -> TypeJ {
        let mut imm: u32 = 0;

        imm |= (instruction >> 20) & 0b11111111110;
        imm |= (instruction & 0x00100000) >> 9;
        imm |= instruction & 0x000FF000;
        imm |= (((instruction & 0x80000000) as i32) >> 11) as u32;

        TypeJ {
            rd: ((instruction >> 7) & 0b11111) as usize,
            imm: imm as i32 as i64,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct TypeI {
    pub(crate) rd: usize,
    pub(crate) funct3: u64,
    pub(crate) rs1: usize,
    pub(crate) imm: i64,
}
impl TypeI {
    pub(crate) fn decode(instruction: u32) -> TypeI {
        TypeI {
            rd: ((instruction >> 7) & 0b11111) as usize,
            funct3: ((instruction >> 12) & 0b111) as u64,
            rs1: ((instruction >> 15) & 0b11111) as usize,
            imm: ((instruction as i32) >> 20) as i64,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct TypeB {
    pub(crate) funct3: u64,
    pub(crate) rs1: usize,
    pub(crate) rs2: usize,
    pub(crate) imm: i64,
}
impl TypeB {
    pub(crate) fn decode(instruction: u32) -> TypeB {
        let mut imm: u32 = 0;

        imm |= (instruction >> 7) & 0b11110;
        imm |= (instruction >> 20) & 0b11111100000;
        imm |= (instruction & 0b10000000) << 4;
        imm |= (((instruction & 0x80000000) as i32) >> 19) as u32;

        TypeB {
            funct3: ((instruction >> 12) & 0b111) as u64,
            rs1: ((instruction >> 15) & 0b11111) as usize,
            rs2: ((instruction >> 20) & 0b11111) as usize,
            imm: imm as i32 as i64,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct TypeS {
    pub(crate) rs1: usize,
    pub(crate) rs2: usize,
    pub(crate) funct3: u64,
    pub(crate) imm: i64,
}
impl TypeS {
    pub(crate) fn decode(instruction: u32) -> TypeS {
        let mut imm: u32 = 0;

        imm |= (instruction >> 7) & 0b11111;
        imm |= (((instruction as i32) >> 20) as u32) & 0xFFFFFFE0;

        TypeS {
            funct3: ((instruction >> 12) & 0b111) as u64,
            rs1: ((instruction >> 15) & 0b11111) as usize,
            rs2: ((instruction >> 20) & 0b11111) as usize,
            imm: imm as i32 as i64,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct TypeR {
    pub(crate) rd: usize,
    pub(crate) rs1: usize,
    pub(crate) rs2: usize,
    pub(crate) funct3: u64,
    pub(crate) funct7: u64,
}
impl TypeR {
    pub(crate) fn decode(instruction: u32) -> TypeR {
        TypeR {
            rd: ((instruction >> 7) & 0b11111) as usize,
            rs1: ((instruction >> 15) & 0b11111) as usize,
            rs2: ((instruction >> 20) & 0b11111) as usize,
            funct3: ((instruction >> 12) & 0b111) as u64,
            funct7: ((instruction >> 25) & 0b1111111) as u64,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) struct TypeR4 {
    pub(crate) rd: usize,
    pub(crate) rs1: usize,
    pub(crate) rs2: usize,
    pub(crate) funct3: u64,
    pub(crate) funct2: u64,
    pub(crate) rs3: usize,
}
impl TypeR4 {
    pub(crate) fn decode(instruction: u32) -> TypeR4 {
        TypeR4 {
            rd: ((instruction >> 7) & 0b11111) as usize,
            rs1: ((instruction >> 15) & 0b11111) as usize,
            rs2: ((instruction >> 20) & 0b11111) as usize,
            funct3: ((instruction >> 12) & 0b111) as u64,
            funct2: ((instruction >> 25) & 0b11) as u64,
            rs3: (instruction >> 27) as usize,
        }
    }
}

/// Instructions belonging to the base 32-bit integer instruction set
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum RV32I {
    LUI(TypeU),
    AUIPC(TypeU),
    JAL(TypeJ),
    JALR(TypeI),
    BEQ(TypeB),
    BNE(TypeB),
    BLT(TypeB),
    BGE(TypeB),
    BLTU(TypeB),
    BGEU(TypeB),
    LB(TypeI),
    LH(TypeI),
    LW(TypeI),
    LBU(TypeI),
    LHU(TypeI),
    SB(TypeS),
    SH(TypeS),
    SW(TypeS),
    ADDI(TypeI),
    SLTI(TypeI),
    SLTIU(TypeI),
    XORI(TypeI),
    ORI(TypeI),
    ANDI(TypeI),
    //SLLI(TypeI),
    //SRLI(TypeI),
    //SRAI(TypeI),
    ADD(TypeR),
    SUB(TypeR),
    SLL(TypeR),
    SLT(TypeR),
    SLTU(TypeR),
    XOR(TypeR),
    SRL(TypeR),
    SRA(TypeR),
    OR(TypeR),
    AND(TypeR),
    FENCE(TypeI),
    ECALL(TypeI),
    EBREAK(TypeI),
}

/// Instructions belonging to the base 64-bit integer instruction set
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum RV64I {
    LWU(TypeI),
    LD(TypeI),
    SD(TypeS),
    SLLI(TypeI),
    SRLI(TypeI),
    SRAI(TypeI),
    ADDIW(TypeI),
    SLLIW(TypeI),
    SRLIW(TypeI),
    SRAIW(TypeI),
    ADDW(TypeR),
    SUBW(TypeR),
    SLLW(TypeR),
    SRLW(TypeR),
    SRAW(TypeR),
}

/// Instructions belonging to the 32-bit A extension
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum RV32A {
    LR(TypeR),
    SC(TypeR),
    AMOSWAP(TypeR),
    AMOADD(TypeR),
    AMOXOR(TypeR),
    AMOAND(TypeR),
    AMOOR(TypeR),
    AMOMIN(TypeR),
    AMOMAX(TypeR),
    AMOMINU(TypeR),
    AMOMAXU(TypeR),
}

/// Instructions belonging to the 64-bit A extension
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum RV64A {
    LR(TypeR),
    SC(TypeR),
    AMOSWAP(TypeR),
    AMOADD(TypeR),
    AMOXOR(TypeR),
    AMOAND(TypeR),
    AMOOR(TypeR),
    AMOMIN(TypeR),
    AMOMAX(TypeR),
    AMOMINU(TypeR),
    AMOMAXU(TypeR),
}

/// Instructions belonging to the 32-bit extension F
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum RV32F {
    FLW(TypeI),
    FSW(TypeS),
    FMADD(TypeR4),
    FMSUB(TypeR4),
    FNMSUB(TypeR4),
    FNMADD(TypeR4),
    FADD(TypeR),
    FSUB(TypeR),
    FMUL(TypeR),
    FDIV(TypeR),
    FSQRT(TypeR),
    FSGNJ(TypeR),
    FSGNJN(TypeR),
    FSGNJX(TypeR),
    FMIN(TypeR),
    FMAX(TypeR),
    FCVT_WS(TypeR),
    FCVT_WUS(TypeR),
    FMV_XW(TypeR),
    FEQ(TypeR),
    FLT(TypeR),
    FLE(TypeR),
    FCLASS(TypeR),
    FCVT_SW(TypeR),
    FCVT_SWU(TypeR),
    FMV_WX(TypeR),
}

/// Instructions belonging to the RV64F instruction set
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum RV64F {
    FCVT_LS(TypeR),
    FCVT_LUS(TypeR),
    FCVT_SL(TypeR),
    FCVT_SLU(TypeR),
}

/// Instructions belonging to the RV32D instruction set
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum RV32D {
    FLD(TypeI),
    FSD(TypeS),
    FMADD(TypeR4),
    FMSUB(TypeR4),
    FNMSUB(TypeR4),
    FNMADD(TypeR4),
    FADD(TypeR),
    FSUB(TypeR),
    FMUL(TypeR),
    FDIV(TypeR),
    FSQRT(TypeR),
    FSGNJ(TypeR),
    FSGNJN(TypeR),
    FSGNJX(TypeR),
    FMIN(TypeR),
    FMAX(TypeR),
    FCVT_SD(TypeR),
    FCVT_DS(TypeR),
    FEQ(TypeR),
    FLT(TypeR),
    FLE(TypeR),
    FCLASS(TypeR),
    FCVT_WD(TypeR),
    FCVT_WUD(TypeR),
    FCVT_DW(TypeR),
    FCVT_DWU(TypeR),
}

/// Instructions belonging to the RV64D instruction set
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum RV64D {
    FCVT_LD(TypeR),
    FCVT_LUD(TypeR),
    FMV_XD(TypeR),
    FCVT_DL(TypeR),
    FCVT_DLU(TypeR),
    FMV_DX(TypeR),
}

/// Instructions belonging to the Zicsr instruction set
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum CSR {
    RW(TypeI),
    RS(TypeI),
    RC(TypeI),
    RWI(TypeI),
    RSI(TypeI),
    RCI(TypeI),
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum RV32M {
    MUL(TypeR),
    MULH(TypeR),
    MULHSU(TypeR),
    MULHU(TypeR),
    DIV(TypeR),
    DIVU(TypeR),
    REM(TypeR),
    REMU(TypeR),
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum RV64M {
    MULW(TypeR),
    DIVW(TypeR),
    DIVUW(TypeR),
    REMW(TypeR),
    REMUW(TypeR),
}

/// The collection of supported instruction sets
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum InstructionSet {
    RV32I(RV32I),
    RV64I(RV64I),
    RV32A(RV32A),
    RV64A(RV64A),
    RV32F(RV32F),
    RV64F(RV64F),
    RV32D(RV32D),
    RV64D(RV64D),
    CSR(CSR),
    RV32M(RV32M),
    RV64M(RV64M),
    Unknown(u32),
}

/// Given a RISC-V instruction as a 32-bit integer,
/// decode it and return information about
///  - which instruction set it belongs to
///  - what instruction it is
///  - its arguments
pub(crate) fn decode(buf: &[u8]) -> InstructionSet {
    let instruction = u32::from_le_bytes(buf[..4].try_into().unwrap());
    match instruction & 0b1111111 {
        0b0000011 => {
            let args = TypeI::decode(instruction);

            match args.funct3 {
                0b110 => InstructionSet::RV64I(RV64I::LWU(args)),
                0b011 => InstructionSet::RV64I(RV64I::LD(args)),
                0b000 => InstructionSet::RV32I(RV32I::LB(args)),
                0b001 => InstructionSet::RV32I(RV32I::LH(args)),
                0b010 => InstructionSet::RV32I(RV32I::LW(args)),
                0b100 => InstructionSet::RV32I(RV32I::LBU(args)),
                0b101 => InstructionSet::RV32I(RV32I::LHU(args)),
                _ => InstructionSet::Unknown(instruction),
            }
        },
        0b0100011 => {
            let args = TypeS::decode(instruction);

            match args.funct3 {
                0b011 => InstructionSet::RV64I(RV64I::SD(args)),
                0b000 => InstructionSet::RV32I(RV32I::SB(args)),
                0b001 => InstructionSet::RV32I(RV32I::SH(args)),
                0b010 => InstructionSet::RV32I(RV32I::SW(args)),
                _ => InstructionSet::Unknown(instruction),
            }
        },
        0b0010011 => {
            let mut args = TypeI::decode(instruction);

            match args.funct3 {
                0b001 => {
                    if args.imm & 0b111111000000 == 0 {
                        InstructionSet::RV64I(RV64I::SLLI(args))
                    } else {
                        InstructionSet::Unknown(instruction)
                    }
                },
                0b101 => {
                    if args.imm & 0b111111000000 == 0b010000000000 {
                        args.imm &= 0b111111;
                        InstructionSet::RV64I(RV64I::SRAI(args))
                    } else if args.imm & 0b111111000000 == 0 {
                        InstructionSet::RV64I(RV64I::SRLI(args))
                    } else {
                        InstructionSet::Unknown(instruction)
                    }
                },
                0b000 => InstructionSet::RV32I(RV32I::ADDI(args)),
                0b010 => InstructionSet::RV32I(RV32I::SLTI(args)),
                0b011 => InstructionSet::RV32I(RV32I::SLTIU(args)),
                0b100 => InstructionSet::RV32I(RV32I::XORI(args)),
                0b110 => InstructionSet::RV32I(RV32I::ORI(args)),
                0b111 => InstructionSet::RV32I(RV32I::ANDI(args)),
                _ => InstructionSet::Unknown(instruction),
            }
        },
        0b0011011 => {
            let mut args = TypeI::decode(instruction);

            match args.funct3 {
                0b000 => InstructionSet::RV64I(RV64I::ADDIW(args)),
                0b001 => {
                    if args.imm & 0b111111100000 == 0 {
                        InstructionSet::RV64I(RV64I::SLLIW(args))
                    } else {
                        InstructionSet::Unknown(instruction)
                    }
                },
                0b101 => {
                    if args.imm & 0b111111100000 == 0b010000000000 {
                        args.imm &= 0b11111;
                        InstructionSet::RV64I(RV64I::SRAIW(args))
                    } else if args.imm & 0b111111100000 == 0 {
                        InstructionSet::RV64I(RV64I::SRLIW(args))
                    } else {
                        InstructionSet::Unknown(instruction)
                    }
                },
                _ => InstructionSet::Unknown(instruction),
            }
        },
        0b0111011 => {
            let args = TypeR::decode(instruction);

            match args.funct7 {
                0b0000000 => match args.funct3 {
                    0b000 => InstructionSet::RV64I(RV64I::ADDW(args)),
                    0b001 => InstructionSet::RV64I(RV64I::SLLW(args)),
                    0b101 => InstructionSet::RV64I(RV64I::SRLW(args)),
                    _ => InstructionSet::Unknown(instruction),
                },
                0b0100000 => {
                    if args.funct3 == 0b000 {
                        InstructionSet::RV64I(RV64I::SUBW(args))
                    } else if args.funct3 == 0b101 {
                        InstructionSet::RV64I(RV64I::SRAW(args))
                    } else {
                        InstructionSet::Unknown(instruction)
                    }
                },
                0b0000001 => match args.funct3 {
                    0b000 => InstructionSet::RV64M(RV64M::MULW(args)),
                    0b100 => InstructionSet::RV64M(RV64M::DIVW(args)),
                    0b101 => InstructionSet::RV64M(RV64M::DIVUW(args)),
                    0b110 => InstructionSet::RV64M(RV64M::REMW(args)),
                    0b111 => InstructionSet::RV64M(RV64M::REMUW(args)),
                    _ => InstructionSet::Unknown(instruction),
                },
                _ => InstructionSet::Unknown(instruction),
            }
        },
        0b0110111 => InstructionSet::RV32I(RV32I::LUI(TypeU::decode(instruction))),
        0b0010111 => InstructionSet::RV32I(RV32I::AUIPC(TypeU::decode(instruction))),
        0b1101111 => InstructionSet::RV32I(RV32I::JAL(TypeJ::decode(instruction))),
        0b1100111 => {
            let args = TypeI::decode(instruction);

            if args.funct3 != 0 {
                InstructionSet::Unknown(instruction)
            } else {
                InstructionSet::RV32I(RV32I::JALR(args))
            }
        },
        0b1100011 => {
            let args = TypeB::decode(instruction);

            match args.funct3 {
                0b000 => InstructionSet::RV32I(RV32I::BEQ(args)),
                0b001 => InstructionSet::RV32I(RV32I::BNE(args)),
                0b100 => InstructionSet::RV32I(RV32I::BLT(args)),
                0b101 => InstructionSet::RV32I(RV32I::BGE(args)),
                0b110 => InstructionSet::RV32I(RV32I::BLTU(args)),
                0b111 => InstructionSet::RV32I(RV32I::BGEU(args)),
                _ => InstructionSet::Unknown(instruction),
            }
        },
        0b0110011 => {
            let args = TypeR::decode(instruction);

            match args.funct7 {
                0b0000001 => match args.funct3 {
                    0b000 => InstructionSet::RV32M(RV32M::MUL(args)),
                    0b001 => InstructionSet::RV32M(RV32M::MULH(args)),
                    0b010 => InstructionSet::RV32M(RV32M::MULHSU(args)),
                    0b011 => InstructionSet::RV32M(RV32M::MULHU(args)),
                    0b100 => InstructionSet::RV32M(RV32M::DIV(args)),
                    0b101 => InstructionSet::RV32M(RV32M::DIVU(args)),
                    0b110 => InstructionSet::RV32M(RV32M::REM(args)),
                    0b111 => InstructionSet::RV32M(RV32M::REMU(args)),
                    _ => InstructionSet::Unknown(instruction),
                },
                0b0100000 => {
                    if args.funct3 == 0b000 {
                        InstructionSet::RV32I(RV32I::SUB(args))
                    } else if args.funct3 == 0b101 {
                        InstructionSet::RV32I(RV32I::SRA(args))
                    } else {
                        InstructionSet::Unknown(instruction)
                    }
                },
                0b0000000 => match args.funct3 {
                    0b000 => InstructionSet::RV32I(RV32I::ADD(args)),
                    0b001 => InstructionSet::RV32I(RV32I::SLL(args)),
                    0b010 => InstructionSet::RV32I(RV32I::SLT(args)),
                    0b011 => InstructionSet::RV32I(RV32I::SLTU(args)),
                    0b100 => InstructionSet::RV32I(RV32I::XOR(args)),
                    0b101 => InstructionSet::RV32I(RV32I::SRL(args)),
                    0b110 => InstructionSet::RV32I(RV32I::OR(args)),
                    0b111 => InstructionSet::RV32I(RV32I::AND(args)),
                    _ => InstructionSet::Unknown(instruction),
                },
                _ => InstructionSet::Unknown(instruction),
            }
        },
        0b0001111 => {
            let args = TypeI::decode(instruction);

            if args.funct3 == 0 && args.rd == 0 && args.rs1 == 0 {
                if (args.imm >> 8) & 0b1111 == 0 {
                    InstructionSet::RV32I(RV32I::FENCE(args))
                } else {
                    InstructionSet::Unknown(instruction)
                }
            } else {
                InstructionSet::Unknown(instruction)
            }
        },
        0b1110011 => {
            let mut args = TypeI::decode(instruction);

            if args.rd == 0 && args.rs1 == 0 && args.funct3 == 0 {
                match args.imm {
                    0 => InstructionSet::RV32I(RV32I::ECALL(args)),
                    1 => InstructionSet::RV32I(RV32I::EBREAK(args)),
                    _ => InstructionSet::Unknown(instruction),
                }
            } else {
                args.imm &= 0xFFF;

                match args.funct3 {
                    0b001 => InstructionSet::CSR(CSR::RW(args)),
                    0b010 => InstructionSet::CSR(CSR::RS(args)),
                    0b011 => InstructionSet::CSR(CSR::RC(args)),
                    0b101 => InstructionSet::CSR(CSR::RWI(args)),
                    0b110 => InstructionSet::CSR(CSR::RSI(args)),
                    0b111 => InstructionSet::CSR(CSR::RCI(args)),
                    _ => InstructionSet::Unknown(instruction),
                }
            }
        },
        0b0101111 => {
            let args = TypeR::decode(instruction);

            match args.funct3 {
                0b011 => match args.funct7 >> 2 {
                    0b00010 => {
                        if args.rs2 == 0 {
                            InstructionSet::RV64A(RV64A::LR(args))
                        } else {
                            InstructionSet::Unknown(instruction)
                        }
                    },
                    0b00011 => InstructionSet::RV64A(RV64A::SC(args)),
                    0b00001 => InstructionSet::RV64A(RV64A::AMOSWAP(args)),
                    0b00000 => InstructionSet::RV64A(RV64A::AMOADD(args)),
                    0b00100 => InstructionSet::RV64A(RV64A::AMOXOR(args)),
                    0b01100 => InstructionSet::RV64A(RV64A::AMOAND(args)),
                    0b01000 => InstructionSet::RV64A(RV64A::AMOOR(args)),
                    0b10000 => InstructionSet::RV64A(RV64A::AMOMIN(args)),
                    0b10100 => InstructionSet::RV64A(RV64A::AMOMAX(args)),
                    0b11000 => InstructionSet::RV64A(RV64A::AMOMINU(args)),
                    0b11100 => InstructionSet::RV64A(RV64A::AMOMAXU(args)),
                    _ => InstructionSet::Unknown(instruction),
                },
                0b010 => match args.funct7 >> 2 {
                    0b00010 => {
                        if args.rs2 == 0 {
                            InstructionSet::RV32A(RV32A::LR(args))
                        } else {
                            InstructionSet::Unknown(instruction)
                        }
                    },
                    0b00011 => InstructionSet::RV32A(RV32A::SC(args)),
                    0b00001 => InstructionSet::RV32A(RV32A::AMOSWAP(args)),
                    0b00000 => InstructionSet::RV32A(RV32A::AMOADD(args)),
                    0b00100 => InstructionSet::RV32A(RV32A::AMOXOR(args)),
                    0b01100 => InstructionSet::RV32A(RV32A::AMOAND(args)),
                    0b01000 => InstructionSet::RV32A(RV32A::AMOOR(args)),
                    0b10000 => InstructionSet::RV32A(RV32A::AMOMIN(args)),
                    0b10100 => InstructionSet::RV32A(RV32A::AMOMAX(args)),
                    0b11000 => InstructionSet::RV32A(RV32A::AMOMINU(args)),
                    0b11100 => InstructionSet::RV32A(RV32A::AMOMAXU(args)),
                    _ => InstructionSet::Unknown(instruction),
                },
                _ => InstructionSet::Unknown(instruction),
            }
        },
        0b1010011 => {
            let args = TypeR::decode(instruction);

            match args.funct7 {
                0b1100000 => match args.rs2 {
                    0b00010 => InstructionSet::RV64F(RV64F::FCVT_LS(args)),
                    0b00011 => InstructionSet::RV64F(RV64F::FCVT_LUS(args)),
                    0b00000 => InstructionSet::RV32F(RV32F::FCVT_WS(args)),
                    0b00001 => InstructionSet::RV32F(RV32F::FCVT_WUS(args)),
                    _ => InstructionSet::Unknown(instruction),
                },
                0b1101000 => match args.rs2 {
                    0b00010 => InstructionSet::RV64F(RV64F::FCVT_SL(args)),
                    0b00011 => InstructionSet::RV64F(RV64F::FCVT_SLU(args)),
                    0b00000 => InstructionSet::RV32F(RV32F::FCVT_SW(args)),
                    0b00001 => InstructionSet::RV32F(RV32F::FCVT_SWU(args)),
                    _ => InstructionSet::Unknown(instruction),
                },
                0b0000000 => InstructionSet::RV32F(RV32F::FADD(args)),
                0b0000100 => InstructionSet::RV32F(RV32F::FSUB(args)),
                0b0001000 => InstructionSet::RV32F(RV32F::FMUL(args)),
                0b0001100 => InstructionSet::RV32F(RV32F::FDIV(args)),
                0b0101100 => {
                    if args.rs2 == 0 {
                        InstructionSet::RV32F(RV32F::FSQRT(args))
                    } else {
                        InstructionSet::Unknown(instruction)
                    }
                },
                0b0010000 => match args.funct3 {
                    0b000 => InstructionSet::RV32F(RV32F::FSGNJ(args)),
                    0b001 => InstructionSet::RV32F(RV32F::FSGNJN(args)),
                    0b010 => InstructionSet::RV32F(RV32F::FSGNJX(args)),
                    _ => InstructionSet::Unknown(instruction),
                },
                0b0010100 => match args.funct3 {
                    0b000 => InstructionSet::RV32F(RV32F::FMIN(args)),
                    0b001 => InstructionSet::RV32F(RV32F::FMAX(args)),
                    _ => InstructionSet::Unknown(instruction),
                },
                0b1110000 => {
                    if args.rs2 == 0 {
                        match args.funct3 {
                            0b000 => InstructionSet::RV32F(RV32F::FMV_XW(args)),
                            0b001 => InstructionSet::RV32F(RV32F::FCLASS(args)),
                            _ => InstructionSet::Unknown(instruction),
                        }
                    } else {
                        InstructionSet::Unknown(instruction)
                    }
                },
                0b1010000 => match args.funct3 {
                    0b010 => InstructionSet::RV32F(RV32F::FEQ(args)),
                    0b001 => InstructionSet::RV32F(RV32F::FLT(args)),
                    0b000 => InstructionSet::RV32F(RV32F::FLE(args)),
                    _ => InstructionSet::Unknown(instruction),
                },
                0b1111000 => {
                    if args.rs2 == 0 && args.funct3 == 0 {
                        InstructionSet::RV32F(RV32F::FMV_WX(args))
                    } else {
                        InstructionSet::Unknown(instruction)
                    }
                },
                0b1100001 => match args.rs2 {
                    0b00010 => InstructionSet::RV64D(RV64D::FCVT_LD(args)),
                    0b00011 => InstructionSet::RV64D(RV64D::FCVT_LUD(args)),
                    0b00000 => InstructionSet::RV32D(RV32D::FCVT_WD(args)),
                    0b00001 => InstructionSet::RV32D(RV32D::FCVT_WUD(args)),
                    _ => InstructionSet::Unknown(instruction),
                },
                0b1110001 => {
                    if args.rs2 == 0 {
                        match args.funct3 {
                            0 => InstructionSet::RV64D(RV64D::FMV_XD(args)),
                            1 => InstructionSet::RV32D(RV32D::FCLASS(args)),
                            _ => InstructionSet::Unknown(instruction),
                        }
                    } else {
                        InstructionSet::Unknown(instruction)
                    }
                },
                0b1101001 => match args.rs2 {
                    0b00000 => {
                        if args.funct3 == 0 {
                            InstructionSet::RV32D(RV32D::FCVT_DW(args))
                        } else {
                            InstructionSet::Unknown(instruction)
                        }
                    },
                    0b00001 => {
                        if args.funct3 == 0 {
                            InstructionSet::RV32D(RV32D::FCVT_DWU(args))
                        } else {
                            InstructionSet::Unknown(instruction)
                        }
                    },
                    0b00010 => InstructionSet::RV64D(RV64D::FCVT_DL(args)),
                    0b00011 => InstructionSet::RV64D(RV64D::FCVT_DLU(args)),
                    _ => InstructionSet::Unknown(instruction),
                },
                0b1111001 => {
                    if args.rs2 == 0 && args.funct3 == 0 {
                        InstructionSet::RV64D(RV64D::FMV_DX(args))
                    } else {
                        InstructionSet::Unknown(instruction)
                    }
                },
                0b0000001 => InstructionSet::RV32D(RV32D::FADD(args)),
                0b0000101 => InstructionSet::RV32D(RV32D::FSUB(args)),
                0b0001001 => InstructionSet::RV32D(RV32D::FMUL(args)),
                0b0001101 => InstructionSet::RV32D(RV32D::FDIV(args)),
                0b0101101 => {
                    if args.rs2 == 0 {
                        InstructionSet::RV32D(RV32D::FSQRT(args))
                    } else {
                        InstructionSet::Unknown(instruction)
                    }
                },
                0b0010001 => match args.funct3 {
                    0b000 => InstructionSet::RV32D(RV32D::FSGNJ(args)),
                    0b001 => InstructionSet::RV32D(RV32D::FSGNJN(args)),
                    0b010 => InstructionSet::RV32D(RV32D::FSGNJX(args)),
                    _ => InstructionSet::Unknown(instruction),
                },
                0b0010101 => match args.funct3 {
                    0b000 => InstructionSet::RV32D(RV32D::FMIN(args)),
                    0b001 => InstructionSet::RV32D(RV32D::FMAX(args)),
                    _ => InstructionSet::Unknown(instruction),
                },
                0b0100000 => {
                    if args.rs2 == 0b00001 {
                        InstructionSet::RV32D(RV32D::FCVT_SD(args))
                    } else {
                        InstructionSet::Unknown(instruction)
                    }
                },
                0b0100001 => {
                    if args.rs2 == 0 && args.funct3 == 0 {
                        InstructionSet::RV32D(RV32D::FCVT_DS(args))
                    } else {
                        InstructionSet::Unknown(instruction)
                    }
                },
                0b1010001 => match args.funct3 {
                    0b010 => InstructionSet::RV32D(RV32D::FEQ(args)),
                    0b001 => InstructionSet::RV32D(RV32D::FLT(args)),
                    0b000 => InstructionSet::RV32D(RV32D::FLE(args)),
                    _ => InstructionSet::Unknown(instruction),
                },
                _ => InstructionSet::Unknown(instruction),
            }
        },
        0b0000111 => {
            let args = TypeI::decode(instruction);

            match args.funct3 {
                0b010 => InstructionSet::RV32F(RV32F::FLW(args)),
                0b011 => InstructionSet::RV32D(RV32D::FLD(args)),
                _ => InstructionSet::Unknown(instruction),
            }
        },
        0b0100111 => {
            let args = TypeS::decode(instruction);

            match args.funct3 {
                0b010 => InstructionSet::RV32F(RV32F::FSW(args)),
                0b011 => InstructionSet::RV32D(RV32D::FSD(args)),
                _ => InstructionSet::Unknown(instruction),
            }
        },
        0b1000011 => {
            let args = TypeR4::decode(instruction);

            match args.funct2 {
                0 => InstructionSet::RV32F(RV32F::FMADD(args)),
                1 => InstructionSet::RV32D(RV32D::FMADD(args)),
                _ => InstructionSet::Unknown(instruction),
            }
        },
        0b1000111 => {
            let args = TypeR4::decode(instruction);

            match args.funct2 {
                0 => InstructionSet::RV32F(RV32F::FMSUB(args)),
                1 => InstructionSet::RV32D(RV32D::FMSUB(args)),
                _ => InstructionSet::Unknown(instruction),
            }
        },
        0b1001011 => {
            let args = TypeR4::decode(instruction);

            match args.funct2 {
                0 => InstructionSet::RV32F(RV32F::FNMSUB(args)),
                1 => InstructionSet::RV32D(RV32D::FNMSUB(args)),
                _ => InstructionSet::Unknown(instruction),
            }
        },
        0b1001111 => {
            let args = TypeR4::decode(instruction);

            match args.funct2 {
                0 => InstructionSet::RV32F(RV32F::FNMADD(args)),
                1 => InstructionSet::RV32D(RV32D::FNMADD(args)),
                _ => InstructionSet::Unknown(instruction),
            }
        },
        _ => InstructionSet::Unknown(instruction),
    }
}
