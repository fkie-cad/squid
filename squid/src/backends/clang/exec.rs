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

/// The raw return code of the "JIT", i.e. the AOT-compiled C code.
#[repr(u32)]
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum JITReturnCode {
    Event = 0,
    InvalidState = 1,
    InvalidJumpTarget = 2,
    InvalidRead = 3,
    UninitializedRead = 4,
    End = 5,
    InvalidWrite = 6,
    InvalidEventChannel = 7,
    DivByZero = 8,
    Timeout = 9,
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct JITReturnBuffer {
    /// Corresponds to JITReturnCode
    pub(crate) code: u32,
    pub(crate) arg0: usize,
    pub(crate) arg1: usize,
    pub(crate) count: usize,
}

type JITEntrypoint = extern "C" fn(usize, usize, usize, usize, usize) -> usize;

pub(crate) struct JITExecutor {
    entrypoint: JITEntrypoint,
    return_buf: JITReturnBuffer,
}

impl JITExecutor {
    pub(crate) fn new(binary_path: &Path) -> Self {
        let entrypoint = unsafe {
            let lib = Library::new(binary_path).unwrap();
            let f: Symbol<JITEntrypoint> = lib.get(b"run").unwrap();
            let f = *f.deref();
            std::mem::forget(lib);
            f
        };

        Self {
            entrypoint,
            return_buf: JITReturnBuffer::default(),
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
    pub(crate) fn return_code(&self) -> JITReturnCode {
        debug_assert!(self.return_buf.code <= 9);
        unsafe { std::mem::transmute::<u32, JITReturnCode>(self.return_buf.code) }
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
