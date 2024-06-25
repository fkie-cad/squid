//! `ewe` is a compiler wrapper toolset that extracts metadata from C
//! code and stores it in addition to the generated binaries in `.ewe` files.
//! Its primary purpose is to tackle the information loss problem during compilation
//! and reconstruct basic block boundaries in machine code.
//! This enables CFG reconstruction from C code making use of the `goto*` extension.
//!
//! This crate is a helper for [squid](https://github.com/fkie-cad/squid) and is not meant to be
//! generally usable. Use at your own risk.

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
