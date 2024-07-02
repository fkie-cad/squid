use std::{
    ops::Deref,
    path::Path,
};

use libloading::{
    Library,
    Symbol,
};

use crate::{
    backends::clang::{
        EventChannel,
        Memory,
        Registers,
    },
    frontend::VAddr,
};

/// The raw return code of the "AOT", i.e. the AOT-compiled C code.
#[repr(u32)]
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum AOTReturnCode {
    /// The guest threw an event
    Event = 0,
    /// An invalid state of the codegen has been reached. This means that there is an error with the codegen.
    InvalidState = 1,
    /// The guest tried to jump to a virtual address that does not exist or does not contain code.
    InvalidJumpTarget = 2,
    /// The guest tried to read from a virtual address that does not point to readable memory.
    InvalidRead = 3,
    /// The guest tried to read from a virtual address that contains uninitialized data.
    UninitializedRead = 4,
    /// The guest has terminated and execution cannot continue.
    End = 5,
    /// The guest tried to write to a virtual address that does not point to writable memory.
    InvalidWrite = 6,
    /// The event channel does not the exact number of values the guest expected
    InvalidEventChannel = 7,
    /// The guest attempted a division by zero
    DivByZero = 8,
    /// The guest exceed the maximum number of allowed RISC-V instructions
    Timeout = 9,
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct AOTReturnBuffer {
    /// Corresponds to AOTReturnCode
    pub(crate) code: u32,
    pub(crate) arg0: usize,
    pub(crate) arg1: usize,
    pub(crate) count: usize,
}

type AOTEntrypoint = extern "C" fn(usize, usize, usize, usize, usize) -> usize;

pub(crate) struct AOTExecutor {
    entrypoint: AOTEntrypoint,
    return_buf: AOTReturnBuffer,
}

impl AOTExecutor {
    pub(crate) fn new(binary_path: &Path) -> Self {
        let entrypoint = unsafe {
            let lib = Library::new(binary_path).unwrap();
            let f: Symbol<AOTEntrypoint> = lib.get(b"run").unwrap();
            let f = *f.deref();
            std::mem::forget(lib);
            f
        };

        Self {
            entrypoint,
            return_buf: AOTReturnBuffer::default(),
        }
    }

    #[inline]
    pub(crate) fn run(&mut self, memory: &mut Memory, event_channel: &mut EventChannel, registers: &mut Registers, var_storage: &mut Vec<u64>) -> VAddr {
        let next_pc = (self.entrypoint)(
            memory.raw_pointer() as usize,
            event_channel.raw_pointer() as usize,
            registers.raw_pointer() as usize,
            &mut self.return_buf as *mut _ as usize,
            var_storage.as_mut_ptr() as usize,
        );
        next_pc as VAddr
    }

    #[inline]
    pub(crate) fn return_code(&self) -> AOTReturnCode {
        debug_assert!(self.return_buf.code <= 9);
        unsafe { std::mem::transmute::<u32, AOTReturnCode>(self.return_buf.code) }
    }

    #[inline]
    pub(crate) fn return_arg0(&self) -> usize {
        self.return_buf.arg0
    }

    #[inline]
    pub(crate) fn return_arg1(&self) -> usize {
        self.return_buf.arg1
    }

    #[inline]
    pub(crate) fn executed_instructions(&self) -> usize {
        self.return_buf.count
    }
}
