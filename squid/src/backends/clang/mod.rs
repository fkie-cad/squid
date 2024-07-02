//! The `clang` backend provided by `squid`.
//!
//! This backend generates C code from the functions in the process
//! image, compiles the C code with clang as a shared object file and
//! loads that via dlopen() into the address space.
//! We take little detour over clang to get the best possible LLVM codegen
//! and thus the best performance.
//!
//! Our original idea was to just emit the LLVM IR ourselves but no LLVM frontend is
//! as good as clang anyways and C is a lot easier to generate than the LLVM IR, so this solution was
//! less work and yielded better results.

mod address;
#[allow(clippy::module_inception)]
mod backend;
mod codegen;
mod concretize;
mod event;
mod exec;
mod heap;
mod memory;
mod preprocess;
mod registers;
mod runtime;
mod symbol;
mod variables;

pub(crate) use address::{
    get_entrypoint_address,
    AddressLayouter,
    AddressSpace,
};
pub(crate) use codegen::CLifter;
pub use codegen::CLifterError;
pub(crate) use concretize::concretize;
pub(crate) use event::EventChannel;
pub(crate) use exec::AOTExecutor;
pub(crate) use heap::Heap;
pub(crate) use memory::{
    populate_stack,
    Memory,
    PAGE_SIZE,
};
pub(crate) use preprocess::{
    insert_entrypoint,
    insert_guard_pages,
};
pub(crate) use registers::Registers;
pub(crate) use variables::VariableStorage;
pub mod perms;
pub use backend::{
    ClangBackend,
    ClangBackendBuilder,
    ClangBackendError,
};
pub use exec::AOTReturnCode;
pub use heap::{
    HeapChunk,
    HeapError,
};
pub use runtime::{
    ClangRuntime,
    ClangRuntimeFault,
};
pub use symbol::{
    Symbol,
    SymbolType,
    SymbolVisibility,
};
