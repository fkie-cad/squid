use crate::frontend::idmap::Id;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GlobalPointer {
    pub elf: Id,
    pub section: Id,
    pub symbol: Id,
    pub chunk: Id,
    pub offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ThreadLocalPointer {
    pub elf: Id,
    pub local: Id,
    pub offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BasicBlockPointer {
    pub elf: Id,
    pub section: Id,
    pub symbol: Id,
    pub chunk: Id,
    pub bb: Id,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FunctionPointer {
    pub elf: Id,
    pub section: Id,
    pub symbol: Id,
    pub chunk: Id,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Pointer {
    Null,
    Global(GlobalPointer),
    Local(ThreadLocalPointer),
    BasicBlock(BasicBlockPointer),
    Function(FunctionPointer),
}
