use thiserror::Error;

use crate::frontend::{
    ao::cfg::CFGError,
    image::VAddr,
};

/// This error type shows everything that can go wrong when lifting RISC-V code
/// into the ΑΩ IR.
#[derive(Error, Debug)]
pub enum AoError {
    #[error("Invalid operation size: {0}")]
    InvalidOpSize(usize),

    #[error("Invalid jump target address: {0:#x}")]
    InvalidJumpTarget(VAddr),

    #[error("No basic block at address {0:#x}")]
    BasicBlockNotFound(VAddr),

    #[error("{0:?}")]
    CFGError(#[from] CFGError),

    #[error("CFG is disonnected and no ewe metadata was available")]
    CFGDisconnected,

    #[error("Unknown RISC-V instruction: {0:x}")]
    UnknownInstr(u32),

    #[error("Invalid rounding mode: {0}")]
    InvalidRm(u64),

    #[error("Invalid variable type: {0}")]
    InvalidVarType(String),
}
