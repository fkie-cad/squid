use rustc_hash::FxHashMap as HashMap;

use crate::{
    frontend::{
        ao::Op,
        ChunkContent,
        ProcessImage,
    },
    runtime::SnapshotId,
};

pub(crate) struct EventChannel {
    /// `[length] [data...]`
    data: Vec<u64>,
    snapshots: HashMap<SnapshotId, Vec<u64>>,
    capacity: usize,
}

impl EventChannel {
    pub(crate) fn new(image: &ProcessImage) -> Self {
        let mut size = 0;

        for elf in image.iter_elfs() {
            for section in elf.iter_sections() {
                for symbol in section.iter_symbols() {
                    for chunk in symbol.iter_chunks() {
                        if let ChunkContent::Code(func) = chunk.content() {
                            for bb in func.cfg().iter_basic_blocks() {
                                for op in bb.ops() {
                                    match op {
                                        Op::PushEventArgs {
                                            args,
                                        } => {
                                            size = std::cmp::max(size, args.len());
                                        },
                                        Op::CollectEventReturns {
                                            vars,
                                        } => {
                                            size = std::cmp::max(size, vars.len());
                                        },
                                        _ => {},
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Self {
            data: vec![0; 1 + size],
            snapshots: HashMap::default(),
            capacity: size,
        }
    }

    pub(crate) fn get(&self, size: usize) -> Option<&[u64]> {
        self.data.get(1..1 + size)
    }

    pub(crate) fn get_mut(&mut self, size: usize) -> Option<&mut [u64]> {
        self.data.get_mut(1..1 + size)
    }

    pub(crate) fn length(&self) -> usize {
        *(unsafe { self.data.get_unchecked(0) }) as usize
    }

    pub(crate) fn set_length(&mut self, length: usize) {
        *(unsafe { self.data.get_unchecked_mut(0) }) = length as u64;
    }

    pub(crate) fn raw_pointer(&mut self) -> *mut u64 {
        self.data.as_mut_ptr()
    }

    pub(crate) fn take_snapshot(&mut self, id: SnapshotId) {
        self.snapshots.insert(id, self.data.clone());
    }

    pub(crate) fn restore_snapshot_unchecked(&mut self, id: SnapshotId) {
        let snapshot = self.snapshots.get(&id);
        let snapshot = unsafe { snapshot.unwrap_unchecked() };
        self.data.copy_from_slice(snapshot);
    }

    pub(crate) fn delete_snapshot_unchecked(&mut self, id: SnapshotId) {
        self.snapshots.remove(&id);
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }
}
