use crate::frontend::idmap::Id;

/// A symbolic pointer to a global variable in the process image
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GlobalPointer {
    pub elf: Id,
    pub section: Id,
    pub symbol: Id,
    pub chunk: Id,
    pub offset: usize,
}

/// A symbolic pointer to a basic block in a function of the process image
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BasicBlockPointer {
    pub elf: Id,
    pub section: Id,
    pub symbol: Id,
    pub chunk: Id,
    pub bb: Id,
}

/// A symbolic pointer to a function in the process image.
/// Note that the difference to the [`BasicBlockPointer`] is that this pointer
/// always points to the entrypoint bb of a function, even when the entrypoint changes.
#[allow(missing_docs)]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FunctionPointer {
    pub elf: Id,
    pub section: Id,
    pub symbol: Id,
    pub chunk: Id,
}

/// A symbolic pointer that points to a leaf in the process image
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Pointer {
    /// This pointer points nowhere
    Null,

    /// This pointer points to a global variable
    Global(GlobalPointer),

    /// This pointer points to a specific basic block of a function
    BasicBlock(BasicBlockPointer),

    /// This pointer points to a specific function
    Function(FunctionPointer),
}
