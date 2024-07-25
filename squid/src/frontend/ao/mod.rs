//! ΑΩ (ao) stands for "atomic operations" and is the IR of `squid`

mod cfg;
mod error;
mod func;
mod lifter;
mod ops;

pub(crate) use lifter::Lifter;

pub mod engine;
pub mod events;
pub use cfg::{
    BasicBlock,
    CFGError,
    Edge,
    CFG,
};
pub use error::AoError;
pub use func::Function;
pub use ops::{
    ArithmeticBehavior,
    Comparison,
    Half,
    Op,
    Register,
    Signedness,
    Var,
    VarType,
};
