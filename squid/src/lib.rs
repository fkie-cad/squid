//! <h1 align="center"> <img src="https://raw.githubusercontent.com/fkie-cad/squid/refs/heads/main/logo.png" width="100" height="auto"> </h1>
//!
//! `squid` is a RISC-V emulation library with features that make it a powerful tool for vulnerability research and fuzzing.
//!
//! Unlike other emulators, `squid` utilizes AOT instead of JIT compilation and allows you to rewrite your target's code before emulation.
//! During runtime, you get full control over your target by handling all system calls and other events yourself.
//! This makes it easy to create and combine new sanitizers and test programs for all kinds of vulnerabilities, not just memory corruptions.
//!
//! # Where to start
//! Everything in `squid` starts with the [`Compiler`], so have a look at that.
//!
//! # Examples, a wiki and more...
//! ...can be found in the [repository](https://github.com/fkie-cad/squid).
//!
//! # What is supported
//! Binaries compiled with `squid`s own [RISC-V toolchain](https://github.com/fkie-cad/squid/blob/main/wiki/TOOLCHAIN.md) and this special set of flags:
//! ```
//! -fPIE -pie -O0 -g -fno-jump-tables -mno-relax -D__thread=
//! ```
//!
//! # Features
//! - `tui` (enabled by default): Enables animations and fancy loading graphics
//!

#![warn(missing_docs)]
#![feature(btree_extract_if)]

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

pub use compiler::{Loader, Compiler};
pub use logger::Logger;
