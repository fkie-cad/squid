//! `ewe` is a compiler wrapper toolset that extracts metadata from C
//! code and stores it in addition to the generated binaries.
//! Its primary purpose is to tackle the information loss problem during compilation
//! and reconstruct basic block boundaries in machine code.
//! This enables perfect CFG reconstruction even from the most complex C code involving `switch` and `goto*` statements.

mod asm;
mod getopt;
mod listing;

pub mod container;
pub mod env;
pub mod toolchain;
pub use listing::{
    Listing,
    ListingFunction,
    EXTENSION,
};
