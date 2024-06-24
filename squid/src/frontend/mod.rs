//! The frontend handles everything related to symbolic ELF-loading and the creation
//! of the process image

mod chunk;
mod dependency;
mod elf;
mod error;
mod fixedvec;
mod idmap;
mod image;
mod perms;
mod pointer;
mod reloc;
mod section;
mod symbol;
mod tls;

pub(crate) mod symbolization_passes;

pub(crate) use image::ProcessImageBuilder;
pub(crate) use reloc::Relocation;

pub mod ao;
pub use chunk::{
    Chunk,
    ChunkBuilder,
    ChunkContent,
};
pub use elf::{
    Elf,
    ElfBuilder,
};
pub use error::LoaderError;
pub use fixedvec::FixedVec;
pub use idmap::{
    HasId,
    Id,
};
pub use image::{
    ProcessImage,
    VAddr,
};
pub use perms::Perms;
pub use pointer::{
    BasicBlockPointer,
    FunctionPointer,
    GlobalPointer,
    Pointer,
    ThreadLocalPointer,
};
pub use section::{
    Section,
    SectionBuilder,
};
pub use symbol::{
    Symbol,
    SymbolBuilder,
};
pub use tls::{
    ThreadLocal,
    Tls,
    TlsOffset,
};
