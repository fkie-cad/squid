use std::{
    collections::HashMap,
    ops::{
        BitAnd,
        BitOrAssign,
        Not,
        ShlAssign,
    },
};

use num_traits::NumCast;
use rustc_hash::FxHashMap;
use thiserror::Error;

use crate::{
    backends::clang::{
        address::POINTER_CODE_MASK,
        perms::*,
        AddressSpace,
        EventChannel,
        Heap,
        HeapChunk,
        HeapError,
        JITExecutor,
        JITReturnCode,
        Memory,
        Registers,
        Symbol,
    },
    frontend::VAddr,
    kernel::linux::LinuxError,
    riscv::register::{
        CsrRegister,
        FpRegister,
        GpRegister,
    },
    runtime::{
        Runtime,
        SnapshotId,
    },
};

#[derive(Error, Debug, Clone)]
pub enum ClangRuntimeFault {
    #[error("There was an error with the internal state of the JIT: {0}")]
    InternalError(String),

    #[error("Encountered an invalid pc address: {0:#x}")]
    InvalidPc(VAddr),

    #[error("The given snapshot id does not exist: {0}")]
    InvalidSnapshotId(SnapshotId),

    #[error("The application tried to read {0} values from the event channel but only {1} were present")]
    InvalidEventChannel(usize, usize),

    #[error("Reading {1} bytes at address {0:#x} failed")]
    MemoryReadError(VAddr, usize),

    #[error("Writing {1} bytes at address {0:#x} failed")]
    MemoryWriteError(VAddr, usize),

    #[error("Target attempted to divide by zero")]
    DivisionByZero,

    #[error("A memory management error occured: {0}")]
    MemoryManagementError(String),

    #[error("HeapError: {0}")]
    HeapError(#[from] HeapError),

    #[error("LinuxError: {0}")]
    LinuxError(#[from] LinuxError),

    #[error("Timeout")]
    Timeout,

    #[error("Execution cannot continue")]
    End,
}

pub(crate) trait RiscvType: Sized + Copy {
    const SIZE: usize;

    #[inline]
    fn from_slice(data: &[u8]) -> Self {
        debug_assert_eq!(data.len(), Self::SIZE);
        unsafe { *std::mem::transmute::<*const u8, *const Self>(data.as_ptr()) }
    }
}

impl RiscvType for u64 {
    const SIZE: usize = 8;
}

impl RiscvType for u32 {
    const SIZE: usize = 4;
}

impl RiscvType for u16 {
    const SIZE: usize = 2;
}

impl RiscvType for u8 {
    const SIZE: usize = 1;
}

#[inline]
pub(crate) fn broadcast_perm<T>(perm: u8) -> T
where
    T: RiscvType + Default + ShlAssign<i32> + BitOrAssign + NumCast + Copy,
{
    let mut ret = T::default();
    let perms = T::from(perm).unwrap();

    for _ in 0..T::SIZE {
        ret <<= 8;
        ret |= perms;
    }

    ret
}

fn load_riscv_type<T>(memory: &Memory, offset: usize) -> Option<T>
where
    T: RiscvType + Default + ShlAssign<i32> + BitOrAssign + NumCast + Copy + BitAnd,
    <T as BitAnd>::Output: PartialEq<T>,
{
    if !memory.is_in_bounds(offset, T::SIZE) {
        return None;
    }

    /* Check permissions */
    let perms = T::from_slice(memory.perms(offset, T::SIZE));
    let uninit_mask = broadcast_perm::<T>(PERM_UNINIT);

    if (perms & uninit_mask) != T::default() {
        return None;
    }

    let read_mask = broadcast_perm::<T>(PERM_READ);

    if (perms & read_mask) != read_mask {
        return None;
    }

    /* Read content */
    let content = T::from_slice(memory.content(offset, T::SIZE));
    Some(content)
}

fn load_slice(memory: &Memory, offset: usize, size: usize) -> Option<&[u8]> {
    if !memory.is_in_bounds(offset, size) {
        return None;
    }

    /* Check permissions */
    for perm in memory.perms(offset, size) {
        if (*perm & PERM_UNINIT) != 0 || (*perm & PERM_READ) != PERM_READ {
            return None;
        }
    }

    /* Read content */
    let content = memory.content(offset, size);
    Some(content)
}

fn load_slice_mut(memory: &mut Memory, offset: usize, size: usize) -> Option<&mut [u8]> {
    if !memory.is_in_bounds(offset, size) {
        return None;
    }

    /* Check permissions */
    for perm in memory.perms(offset, size) {
        if (*perm & PERM_UNINIT) != 0 || (*perm & PERM_READ) != PERM_READ {
            return None;
        }
    }

    /* Read content */
    let content = memory.content_mut(offset, size);
    Some(content)
}

fn store_riscv_type<T>(memory: &mut Memory, offset: usize, value: T) -> bool
where
    T: RiscvType + Default + ShlAssign<i32> + BitOrAssign + NumCast + Copy + BitAnd<Output = T> + Not<Output = T>,
    <T as BitAnd>::Output: PartialEq<T>,
{
    if !memory.is_in_bounds(offset, T::SIZE) {
        return false;
    }

    /* Check permissions */
    let perms = T::from_slice(memory.perms(offset, T::SIZE));
    let write_mask = broadcast_perm::<T>(PERM_WRITE);

    if (perms & write_mask) != write_mask {
        return false;
    }

    let uninit_mask = broadcast_perm::<T>(PERM_UNINIT);
    let perms = perms & !uninit_mask;

    unsafe {
        *std::mem::transmute::<*mut u8, *mut T>(memory.perms_mut(offset, T::SIZE).as_mut_ptr()) = perms;
    }

    /* Store content */
    unsafe {
        *std::mem::transmute::<*mut u8, *mut T>(memory.content_mut(offset, T::SIZE).as_mut_ptr()) = value;
    }

    true
}

fn store_slice(memory: &mut Memory, offset: usize, value: &[u8]) -> bool {
    let size = value.len();

    if !memory.is_in_bounds(offset, size) {
        return false;
    }

    /* Check permissions */
    for perm in memory.perms_mut(offset, size) {
        if (*perm & PERM_WRITE) != PERM_WRITE {
            return false;
        }

        *perm &= !PERM_UNINIT;
    }

    /* Read content */
    memory.content_mut(offset, size).copy_from_slice(value);

    true
}

fn load_perms(memory: &Memory, offset: usize, size: usize) -> Option<&[u8]> {
    if !memory.is_in_bounds(offset, size) {
        return None;
    }

    Some(memory.perms(offset, size))
}

fn load_perms_mut(memory: &mut Memory, offset: usize, size: usize) -> Option<&mut [u8]> {
    if !memory.is_in_bounds(offset, size) {
        return None;
    }

    Some(memory.perms_mut(offset, size))
}

fn load_string(memory: &Memory, offset: usize) -> Option<&[u8]> {
    if !memory.is_in_bounds(offset, 1) {
        return None;
    }

    for i in offset..memory.size() {
        let perm = memory.perms(i, 1)[0];

        if (perm & PERM_UNINIT) != 0 || (perm & PERM_READ) == 0 {
            return None;
        }

        let byte = memory.content(i, 1)[0];

        if byte == 0 {
            let slice = memory.content(offset, i - offset);
            return Some(slice);
        }
    }

    None
}

fn store_string(memory: &mut Memory, offset: usize, value: &[u8]) -> bool {
    let len = value.len() + 1;

    if !memory.is_in_bounds(offset, len) {
        return false;
    }

    /* Check permissions */
    for perm in memory.perms_mut(offset, len) {
        if (*perm & PERM_WRITE) != PERM_WRITE {
            return false;
        }

        *perm &= !PERM_UNINIT;
    }

    /* Read content */
    let target = memory.content_mut(offset, len);
    target[0..value.len()].copy_from_slice(value);
    target[value.len()] = 0;

    true
}

struct SnapshotData {
    next_pc: VAddr,
    next_event_channel_length: usize,
    var_storage: Vec<u64>,
}

pub struct ClangRuntime {
    memory: Memory,
    event_channel: EventChannel,
    registers: Registers,
    executor: JITExecutor,
    next_pc: VAddr,
    symbols: HashMap<String, Vec<Symbol>>,
    next_event_channel_length: usize,
    snapshots: FxHashMap<SnapshotId, SnapshotData>,
    var_storage: Vec<u64>,
    heap_mgr: Heap,
}

impl ClangRuntime {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        memory: Memory,
        event_channel: EventChannel,
        registers: Registers,
        executor: JITExecutor,
        next_pc: VAddr,
        symbols: HashMap<String, Vec<Symbol>>,
        var_storage: Vec<u64>,
    ) -> Self {
        Self {
            heap_mgr: Heap::new(memory.heap(), memory.heap_end()),
            memory,
            event_channel,
            registers,
            executor,
            next_pc,
            symbols,
            next_event_channel_length: 0,
            snapshots: FxHashMap::default(),
            var_storage,
        }
    }
}

impl Runtime for ClangRuntime {
    type Error = ClangRuntimeFault;
    type Event = usize;

    fn set_pc(&mut self, pc: VAddr) {
        self.registers.set_pc(pc);
        self.next_pc = pc;
    }

    fn get_pc(&self) -> VAddr {
        self.registers.get_pc()
    }

    fn set_gp_register(&mut self, register: GpRegister, value: u64) {
        self.registers.set_gp(register as usize, value);
    }

    fn get_gp_register(&self, register: GpRegister) -> u64 {
        self.registers.get_gp(register as usize)
    }

    fn set_fp_register(&mut self, register: FpRegister, value: f64) {
        self.registers.set_fp(register as usize, value.to_bits());
    }

    fn get_fp_register(&self, register: FpRegister) -> f64 {
        f64::from_bits(self.registers.get_fp(register as usize))
    }

    fn set_csr_register(&mut self, register: CsrRegister, value: u64) {
        self.registers.set_csr(register, value);
    }

    fn get_csr_register(&self, register: CsrRegister) -> u64 {
        self.registers.get_csr(register)
    }

    fn run(&mut self) -> Result<Self::Event, Self::Error> {
        /* Prepare JIT execution */
        self.event_channel.set_length(self.next_event_channel_length);
        self.registers.set_pc(self.next_pc);
        self.registers.set_last_instr(0);

        /* Execute code */
        self.next_pc = self.executor.run(&mut self.memory, &mut self.event_channel, &mut self.registers, &mut self.var_storage);
        self.next_event_channel_length = 0;

        /* Translate jit exit code to runtime event / fault */
        match self.executor.return_code() {
            JITReturnCode::Event => {
                let id = self.executor.return_arg0();
                Ok(id)
            },
            JITReturnCode::InvalidState => Err(ClangRuntimeFault::InternalError("JIT code returned but did not set an event or fault".to_string())),
            JITReturnCode::InvalidJumpTarget => {
                let addr = self.executor.return_arg0() as VAddr;
                Err(ClangRuntimeFault::InvalidPc(addr))
            },
            JITReturnCode::UninitializedRead | JITReturnCode::InvalidRead => {
                let addr = self.executor.return_arg0() as VAddr;
                let size = self.executor.return_arg1();
                Err(ClangRuntimeFault::MemoryReadError(addr, size))
            },
            JITReturnCode::End => Err(ClangRuntimeFault::End),
            JITReturnCode::InvalidWrite => {
                let addr = self.executor.return_arg0() as VAddr;
                let size = self.executor.return_arg1();
                Err(ClangRuntimeFault::MemoryWriteError(addr, size))
            },
            JITReturnCode::InvalidEventChannel => {
                let req_size = self.executor.return_arg0();
                let act_size = self.executor.return_arg1();
                Err(ClangRuntimeFault::InvalidEventChannel(req_size, act_size))
            },
            JITReturnCode::DivByZero => Err(ClangRuntimeFault::DivisionByZero),
            JITReturnCode::Timeout => Err(ClangRuntimeFault::Timeout),
        }
    }

    fn take_snapshot(&mut self, id: SnapshotId) {
        self.snapshots.insert(
            id,
            SnapshotData {
                next_pc: self.next_pc,
                next_event_channel_length: self.next_event_channel_length,
                var_storage: self.var_storage.clone(),
            },
        );
        self.memory.take_snapshot(id);
        self.event_channel.take_snapshot(id);
        self.registers.take_snapshot(id);
        self.heap_mgr.take_snapshot(id);
    }

    fn restore_snapshot(&mut self, id: SnapshotId) -> Result<(), Self::Error> {
        if let Some(snapshot) = self.snapshots.get(&id) {
            self.next_pc = snapshot.next_pc;
            self.next_event_channel_length = snapshot.next_event_channel_length;
            unsafe { std::ptr::copy_nonoverlapping(snapshot.var_storage.as_ptr(), self.var_storage.as_mut_ptr(), snapshot.var_storage.len()) };
        } else {
            return Err(ClangRuntimeFault::InvalidSnapshotId(id));
        }
        self.memory.restore_snapshot_unchecked(id);
        self.event_channel.restore_snapshot_unchecked(id);
        self.registers.restore_snapshot_unchecked(id);
        self.heap_mgr.restore_snapshot_unchecked(id);
        Ok(())
    }

    fn delete_snapshot(&mut self, id: SnapshotId) -> Result<(), Self::Error> {
        if self.snapshots.remove(&id).is_none() {
            return Err(ClangRuntimeFault::InvalidSnapshotId(id));
        }
        self.memory.delete_snapshot_unchecked(id);
        self.event_channel.delete_snapshot_unchecked(id);
        self.registers.delete_snapshot_unchecked(id);
        self.heap_mgr.delete_snapshot_unchecked(id);
        Ok(())
    }

    fn has_snapshot(&self, id: SnapshotId) -> bool {
        self.snapshots.contains_key(&id)
    }

    fn event_channel(&self) -> &[u64] {
        let length = self.event_channel.length();
        self.event_channel.get(length).unwrap()
    }

    fn event_channel_mut(&mut self, size: usize) -> Result<&mut [u64], Self::Error> {
        // Ugly but borrow checker forces us to:
        let cap = self.event_channel.capacity();

        if let Some(data) = self.event_channel.get_mut(size) {
            self.next_event_channel_length = std::cmp::max(self.next_event_channel_length, size);
            Ok(data)
        } else {
            Err(ClangRuntimeFault::InvalidEventChannel(size, cap))
        }
    }

    fn load_dword(&self, address: VAddr) -> Result<u64, Self::Error> {
        let result = match AddressSpace::decode(address) {
            AddressSpace::Code(_) => None,
            AddressSpace::Data(offset) => load_riscv_type(&self.memory, offset),
        };
        result.ok_or(ClangRuntimeFault::MemoryReadError(address, 8))
    }

    fn load_word(&self, address: VAddr) -> Result<u32, Self::Error> {
        let result = match AddressSpace::decode(address) {
            AddressSpace::Code(_) => None,
            AddressSpace::Data(offset) => load_riscv_type(&self.memory, offset),
        };
        result.ok_or(ClangRuntimeFault::MemoryReadError(address, 4))
    }

    fn load_hword(&self, address: VAddr) -> Result<u16, Self::Error> {
        let result = match AddressSpace::decode(address) {
            AddressSpace::Code(_) => None,
            AddressSpace::Data(offset) => load_riscv_type(&self.memory, offset),
        };
        result.ok_or(ClangRuntimeFault::MemoryReadError(address, 2))
    }

    fn load_byte(&self, address: VAddr) -> Result<u8, Self::Error> {
        let result = match AddressSpace::decode(address) {
            AddressSpace::Code(_) => None,
            AddressSpace::Data(offset) => load_riscv_type(&self.memory, offset),
        };
        result.ok_or(ClangRuntimeFault::MemoryReadError(address, 1))
    }

    fn load_slice(&self, address: VAddr, size: usize) -> Result<&[u8], Self::Error> {
        let result = match AddressSpace::decode(address) {
            AddressSpace::Code(_) => None,
            AddressSpace::Data(offset) => load_slice(&self.memory, offset, size),
        };
        result.ok_or(ClangRuntimeFault::MemoryReadError(address, size))
    }

    fn store_dword(&mut self, address: VAddr, value: u64) -> Result<(), Self::Error> {
        let result = match AddressSpace::decode(address) {
            AddressSpace::Code(_) => false,
            AddressSpace::Data(offset) => store_riscv_type(&mut self.memory, offset, value),
        };
        if result {
            Ok(())
        } else {
            Err(ClangRuntimeFault::MemoryWriteError(address, 8))
        }
    }
    fn store_word(&mut self, address: VAddr, value: u32) -> Result<(), Self::Error> {
        let result = match AddressSpace::decode(address) {
            AddressSpace::Code(_) => false,
            AddressSpace::Data(offset) => store_riscv_type(&mut self.memory, offset, value),
        };
        if result {
            Ok(())
        } else {
            Err(ClangRuntimeFault::MemoryWriteError(address, 4))
        }
    }
    fn store_hword(&mut self, address: VAddr, value: u16) -> Result<(), Self::Error> {
        let result = match AddressSpace::decode(address) {
            AddressSpace::Code(_) => false,
            AddressSpace::Data(offset) => store_riscv_type(&mut self.memory, offset, value),
        };
        if result {
            Ok(())
        } else {
            Err(ClangRuntimeFault::MemoryWriteError(address, 2))
        }
    }
    fn store_byte(&mut self, address: VAddr, value: u8) -> Result<(), Self::Error> {
        let result = match AddressSpace::decode(address) {
            AddressSpace::Code(_) => false,
            AddressSpace::Data(offset) => store_riscv_type(&mut self.memory, offset, value),
        };
        if result {
            Ok(())
        } else {
            Err(ClangRuntimeFault::MemoryWriteError(address, 1))
        }
    }

    fn store_slice<S: AsRef<[u8]>>(&mut self, address: VAddr, value: S) -> Result<(), Self::Error> {
        let value = value.as_ref();
        let result = match AddressSpace::decode(address) {
            AddressSpace::Code(_) => false,
            AddressSpace::Data(offset) => store_slice(&mut self.memory, offset, value),
        };
        if result {
            Ok(())
        } else {
            Err(ClangRuntimeFault::MemoryWriteError(address, value.len()))
        }
    }

    fn load_string(&self, address: VAddr) -> Result<&[u8], Self::Error> {
        let result = match AddressSpace::decode(address) {
            AddressSpace::Code(_) => None,
            AddressSpace::Data(offset) => load_string(&self.memory, offset),
        };
        result.ok_or(ClangRuntimeFault::MemoryReadError(address, 0))
    }

    fn store_string<S: AsRef<str>>(&mut self, address: VAddr, value: S) -> Result<(), Self::Error> {
        let value = value.as_ref().as_bytes();
        let result = match AddressSpace::decode(address) {
            AddressSpace::Code(_) => false,
            AddressSpace::Data(offset) => store_string(&mut self.memory, offset, value),
        };
        if result {
            Ok(())
        } else {
            Err(ClangRuntimeFault::MemoryWriteError(address, value.len()))
        }
    }
}

impl ClangRuntime {
    pub fn jit_return_code(&self) -> JITReturnCode {
        self.executor.return_code()
    }

    pub fn permissions(&self, address: VAddr, size: usize) -> Result<&[u8], ClangRuntimeFault> {
        let result = match AddressSpace::decode(address) {
            AddressSpace::Code(_) => None,
            AddressSpace::Data(offset) => load_perms(&self.memory, offset, size),
        };
        result.ok_or(ClangRuntimeFault::MemoryReadError(address, size))
    }

    pub fn permissions_mut(&mut self, address: VAddr, size: usize) -> Result<&mut [u8], ClangRuntimeFault> {
        let result = match AddressSpace::decode(address) {
            AddressSpace::Code(_) => None,
            AddressSpace::Data(offset) => load_perms_mut(&mut self.memory, offset, size),
        };
        result.ok_or(ClangRuntimeFault::MemoryWriteError(address, size))
    }

    pub fn get_last_instruction(&self) -> VAddr {
        self.registers.get_last_instr()
    }

    pub fn load_slice_mut(&mut self, address: VAddr, size: usize) -> Result<&mut [u8], ClangRuntimeFault> {
        let result = match AddressSpace::decode(address) {
            AddressSpace::Code(_) => None,
            AddressSpace::Data(offset) => load_slice_mut(&mut self.memory, offset, size),
        };
        result.ok_or(ClangRuntimeFault::MemoryReadError(address, size))
    }

    pub fn get_executed_instructions(&self) -> usize {
        self.executor.executed_instructions()
    }
}

/// Symbol store
impl ClangRuntime {
    pub fn lookup_symbol_from_address(&self, mut addr: VAddr) -> Vec<(&str, &Symbol)> {
        let mut ret = Vec::new();

        // Codegen mixes native and virtual pointers, only keep the virtual part of code pointers
        if let AddressSpace::Code(mut offset) = AddressSpace::decode(addr) {
            offset &= POINTER_CODE_MASK as usize;
            addr = AddressSpace::Code(offset).encode();
        }

        for (file, symbols) in &self.symbols {
            for symbol in symbols {
                if symbol.contains_address(addr) {
                    ret.push((file.as_str(), symbol));
                }
            }
        }

        ret
    }

    pub fn lookup_symbol_from_private_name<S: AsRef<str>>(&self, name: S) -> Vec<(&str, &Symbol)> {
        let name = name.as_ref();
        let mut ret = Vec::new();

        for (file, symbols) in &self.symbols {
            for symbol in symbols {
                if symbol.is_private() && symbol.name() == name {
                    ret.push((file.as_str(), symbol));
                }
            }
        }

        ret
    }

    pub fn lookup_symbol_from_public_name<S: AsRef<str>>(&self, name: S) -> Vec<(&str, &Symbol)> {
        let name = name.as_ref();
        let mut ret = Vec::new();

        for (file, symbols) in &self.symbols {
            for symbol in symbols {
                if symbol.is_public() && symbol.name() == name {
                    ret.push((file.as_str(), symbol));
                }
            }
        }

        ret
    }
}

/// Dynstore
impl ClangRuntime {
    pub fn dynstore_allocate(&mut self, size: usize) -> Result<VAddr, ClangRuntimeFault> {
        let offset = self.heap_mgr.malloc(&mut self.memory, size)?;
        Ok(AddressSpace::Data(offset).encode())
    }

    pub fn dynstore_deallocate(&mut self, addr: VAddr) -> Result<(), ClangRuntimeFault> {
        if addr == 0 {
            return Ok(());
        }

        let offset = if let AddressSpace::Data(offset) = AddressSpace::decode(addr) {
            offset
        } else {
            return Err(ClangRuntimeFault::MemoryManagementError(format!("Tried to deallocate a non-heap address: {:#x}", addr)));
        };

        self.heap_mgr.free(&mut self.memory, offset)?;

        Ok(())
    }

    pub fn dynstore_get_all_chunks(&self) -> Vec<HeapChunk> {
        self.heap_mgr.get_heap_chunks(&self.memory)
    }

    pub fn dynstore_get_single_chunk(&self, addr: VAddr) -> Result<HeapChunk, ClangRuntimeFault> {
        let offset = if let AddressSpace::Data(offset) = AddressSpace::decode(addr) {
            offset
        } else {
            return Err(ClangRuntimeFault::MemoryManagementError(format!("Tried to get a single chunk with a non-heap address: {:#x}", addr)));
        };

        let chunk = self.heap_mgr.get_heap_chunk(&self.memory, offset)?;

        Ok(chunk)
    }

    pub fn dynstore_has_memory_leaks(&self) -> bool {
        self.heap_mgr.has_mem_leaks()
    }

    pub fn dynstore_reallocate(&mut self, addr: VAddr, new_size: usize) -> Result<VAddr, ClangRuntimeFault> {
        if addr == 0 || new_size == 0 {
            return Err(ClangRuntimeFault::MemoryManagementError("Called dynstore_reallocate() with invalid parameters".to_string()));
        }

        let offset = if let AddressSpace::Data(offset) = AddressSpace::decode(addr) {
            offset
        } else {
            return Err(ClangRuntimeFault::MemoryManagementError(format!("Tried to reallocate a non-heap address: {:#x}", addr)));
        };

        let new_offset = self.heap_mgr.realloc(&mut self.memory, offset, new_size)?;
        Ok(AddressSpace::Data(new_offset).encode())
    }

    pub fn dynstore_reset_leak_tracker(&mut self) {
        self.heap_mgr.reset_count();
    }

    pub fn dynstore_memory_usage(&self) -> usize {
        self.heap_mgr.memory_usage(&self.memory)
    }
}
