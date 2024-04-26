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

#[cfg(test)]
mod tests;

pub(crate) use address::{
    get_entrypoint_address,
    AddressLayouter,
    AddressSpace,
};
pub(crate) use codegen::CLifter;
pub(crate) use concretize::concretize;
pub(crate) use event::EventChannel;
pub(crate) use exec::JITExecutor;
pub(crate) use heap::Heap;
pub(crate) use memory::{
    populate_stack,
    Memory,
    PAGE_SIZE,
};
pub(crate) use preprocess::{
    insert_entrypoint,
    insert_null_page,
};
pub(crate) use registers::Registers;
pub(crate) use variables::VariableStorage;

pub mod perms;
pub use backend::{
    MultiverseBackend,
    MultiverseBackendBuilder,
};
pub use exec::JITReturnCode;
pub use heap::{
    HeapChunk,
    HeapError,
};
pub use runtime::{
    MultiverseRuntime,
    MultiverseRuntimeEvent,
    MultiverseRuntimeFault,
};
pub use symbol::{
    Symbol,
    SymbolType,
    SymbolVisibility,
};
