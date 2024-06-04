use rustc_hash::FxHashMap as HashMap;

use crate::{
    frontend::VAddr,
    riscv::register::CsrRegister,
    runtime::SnapshotId,
};

/// [32x GP] [pc] [instr] [32x FP] [fcsr]
const REGISTER_COUNT: usize = 32 + 1 + 1 + 32 + 1;

pub(crate) const INSTR_INDEX: usize = 33;
pub(crate) const PC_INDEX: usize = 32;

pub(crate) struct Registers {
    content: [u64; REGISTER_COUNT],
    snapshots: HashMap<SnapshotId, [u64; REGISTER_COUNT]>,
}

impl Registers {
    pub(crate) fn new() -> Self {
        Self {
            content: [0; REGISTER_COUNT],
            snapshots: HashMap::default(),
        }
    }

    pub(crate) fn take_snapshot(&mut self, id: SnapshotId) {
        self.snapshots.insert(id, self.content);
    }

    pub(crate) fn restore_snapshot_unchecked(&mut self, id: SnapshotId) {
        let snapshot = self.snapshots.get(&id);
        let snapshot = unsafe { snapshot.unwrap_unchecked() };

        self.content.copy_from_slice(snapshot);
    }

    pub(crate) fn delete_snapshot_unchecked(&mut self, id: SnapshotId) {
        self.snapshots.remove(&id);
    }

    pub(crate) fn get_gp(&self, reg: usize) -> u64 {
        *unsafe { self.content.get_unchecked(reg) }
    }

    pub(crate) fn set_gp(&mut self, reg: usize, value: u64) {
        *unsafe { self.content.get_unchecked_mut(reg) } = value;
    }

    pub(crate) fn get_fp(&self, reg: usize) -> u64 {
        *unsafe { self.content.get_unchecked(34 + reg) }
    }

    pub(crate) fn set_fp(&mut self, reg: usize, value: u64) {
        *unsafe { self.content.get_unchecked_mut(34 + reg) } = value;
    }

    pub(crate) fn get_csr(&self, csr: CsrRegister) -> u64 {
        let value = *unsafe { self.content.get_unchecked(66) };
        match csr {
            CsrRegister::fcsr => value & 0xFF,
            CsrRegister::fflags => value & 0b11111,
            CsrRegister::frm => (value >> 5) & 0b111,
        }
    }

    pub(crate) fn set_csr(&mut self, csr: CsrRegister, value: u64) {
        let old_value = *unsafe { self.content.get_unchecked(66) };
        let new_value = match csr {
            CsrRegister::fcsr => value & 0xFF,
            CsrRegister::fflags => (old_value & 0b11100000) | (value & 0b00011111),
            CsrRegister::frm => (value & 0b11100000) | (old_value & 0b00011111),
        };
        *unsafe { self.content.get_unchecked_mut(64) } = new_value;
    }

    pub(crate) fn get_pc(&self) -> VAddr {
        *unsafe { self.content.get_unchecked(PC_INDEX) } as VAddr
    }

    pub(crate) fn set_pc(&mut self, pc: VAddr) {
        *unsafe { self.content.get_unchecked_mut(PC_INDEX) } = pc;
    }

    pub(crate) fn raw_pointer(&mut self) -> *mut u64 {
        self.content.as_mut_ptr()
    }

    pub(crate) fn get_last_instr(&self) -> VAddr {
        *unsafe { self.content.get_unchecked(INSTR_INDEX) } as VAddr
    }

    pub(crate) fn set_last_instr(&mut self, instr: VAddr) {
        *unsafe { self.content.get_unchecked_mut(INSTR_INDEX) } = instr;
    }
}
