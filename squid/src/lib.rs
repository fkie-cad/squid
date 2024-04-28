//! <h1 align="center"> 🌊 🦑 🌊 </h1><hr/>
//!

#![feature(hash_extract_if)]

mod compiler;
mod listing;
mod logger;

/* Squids interface: */
pub mod backends;
pub mod event;
pub mod frontend;
pub mod kernel;
pub mod passes;
pub mod riscv;
pub mod runtime;

pub use compiler::Compiler;
pub use logger::Logger;
