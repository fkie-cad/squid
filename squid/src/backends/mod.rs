//! Contains all backends that are provided by `squid`

mod backend;
pub mod clang;
pub use backend::Backend;
