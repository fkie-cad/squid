use rustc_hash::FxHashMap;
use thiserror::Error;

use crate::{
    backends::clang::{
        perms::*,
        runtime::broadcast_perm,
        AddressSpace,
        Memory,
    },
    frontend::VAddr,
    runtime::SnapshotId,
};

const PERM_CHUNK_START: u8 = 16;
const PERM_CHUNK_END: u8 = 32;

#[derive(Error, Debug, Clone)]
pub enum HeapError {
    #[error("Attempted to allocate a zero-length chunk")]
    EmptyAllocation,

    #[error("Out of memory trying to allocate {0} bytes")]
    OutOfMemory(usize),

    #[error("The provided address points outside of the heap that is in use: {0:#x}")]
    OutOfBounds(VAddr),

    #[error("Got an address that does not point to a chunk: {0:#x}")]
    NotAChunk(VAddr),
}

#[derive(Debug, Clone)]
pub struct HeapChunk {
    addr: VAddr,
    size: usize,
}

impl HeapChunk {
    pub fn address(&self) -> VAddr {
        self.addr
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

struct SnapshotData {
    cursor: usize,
    count: usize,
    last_size: usize,
}

pub(crate) struct Heap {
    cursor: usize,
    end: usize,
    count: usize,
    last_size: usize,
    snapshots: FxHashMap<SnapshotId, SnapshotData>,
}

impl Heap {
    pub(crate) fn new(heap_start: usize, heap_end: usize) -> Self {
        Self {
            cursor: heap_start,
            end: heap_end,
            count: 0,
            last_size: 0,
            snapshots: FxHashMap::default(),
        }
    }

    pub(crate) fn take_snapshot(&mut self, id: SnapshotId) {
        self.snapshots.insert(
            id,
            SnapshotData {
                cursor: self.cursor,
                count: self.count,
                last_size: self.last_size,
            },
        );
    }

    pub(crate) fn restore_snapshot_unchecked(&mut self, id: SnapshotId) {
        let data = self.snapshots.get(&id);
        let data = unsafe { data.unwrap_unchecked() };

        self.cursor = data.cursor;
        self.count = data.count;
        self.last_size = data.last_size;
    }

    pub(crate) fn delete_snapshot_unchecked(&mut self, id: SnapshotId) {
        self.snapshots.remove(&id);
    }
    
    #[inline]
    fn is_in_bounds(&self, start: usize, len: usize) -> bool {
        start.saturating_add(len) <= self.end
    }

    pub(crate) fn malloc(&mut self, memory: &mut Memory, size: usize) -> Result<usize, HeapError> {
        if size == 0 {
            return Err(HeapError::EmptyAllocation);
        }

        let mut left_redzone_size = size.saturating_sub(self.last_size);
        left_redzone_size += 16 - ((self.cursor + left_redzone_size) & 0xF);
        let memory_usage = left_redzone_size.saturating_add(size.saturating_mul(2));

        if !self.is_in_bounds(self.cursor, memory_usage) {
            return Err(HeapError::OutOfMemory(size));
        }

        /* Left redzone */
        self.cursor += left_redzone_size;
        debug_assert_eq!(self.cursor & 0xF, 0);

        /* chunk */
        let ret = self.cursor;
        let perms = memory.perms_mut(self.cursor - 1, size + 2);

        perms[0] |= PERM_CHUNK_START;

        let num_qwords = size / 8;
        let arr = unsafe { std::mem::transmute::<*mut u8, *mut u64>(perms.as_mut_ptr().add(1)) };
        let arr = unsafe { std::slice::from_raw_parts_mut(arr, num_qwords) };
        let perm_blob = broadcast_perm::<u64>(PERM_READ | PERM_WRITE | PERM_UNINIT);

        for elem in arr {
            *elem = perm_blob;
        }

        for perm in &mut perms[1 + num_qwords * 8..] {
            *perm = PERM_READ | PERM_WRITE | PERM_UNINIT;
        }

        perms[1 + size] |= PERM_CHUNK_END;

        self.cursor += size;

        /* Right redzone */
        self.cursor += size;

        /* Update metadata */
        self.count += 1;
        self.last_size = size;

        Ok(ret)
    }

    pub(crate) fn free(&mut self, memory: &mut Memory, offset: usize) -> Result<(), HeapError> {
        /* Check if offset is in bounds */
        if offset >= self.cursor {
            let vaddr = AddressSpace::Data(offset).encode();
            return Err(HeapError::OutOfBounds(vaddr));
        }

        let offset = offset.saturating_sub(1);
        let rem_size = self.cursor - offset;

        /* Check if we are freeing an actual chunk */
        let perms = memory.perms_mut_raw(offset, rem_size);

        if (perms[0] & PERM_CHUNK_START) == 0 {
            let vaddr = AddressSpace::Data(offset).encode();
            return Err(HeapError::NotAChunk(vaddr));
        }

        /* Clear permissions */
        perms[0] = 0;

        let num_qwords = rem_size / 8;
        let arr = unsafe { std::mem::transmute::<*mut u8, *mut u64>(perms.as_mut_ptr().add(1)) };
        let arr = unsafe { std::slice::from_raw_parts_mut(arr, num_qwords) };
        let perm_mask = broadcast_perm::<u64>(PERM_CHUNK_END);

        let mut modified = 0;

        for elem in arr {
            if (*elem & perm_mask) != 0 {
                break;
            }

            *elem = 0;
            modified += 8;
        }

        for perm in &mut perms[1 + modified..] {
            if (*perm & PERM_CHUNK_END) != 0 {
                break;
            }

            *perm = 0;
            modified += 1;
        }

        memory.mark_dirty(offset, modified);

        /* Update metadata */
        self.count = self.count.saturating_sub(1);

        Ok(())
    }

    pub fn realloc(&mut self, memory: &mut Memory, offset: usize, new_size: usize) -> Result<usize, HeapError> {
        /* Check if offset is in bounds */
        if offset >= self.cursor {
            let vaddr = AddressSpace::Data(offset).encode();
            return Err(HeapError::OutOfBounds(vaddr));
        }

        /* Check if we are reallocating an actual chunk */
        let mut offset = offset.saturating_sub(1);
        let rem_size = self.cursor - offset;
        let perms = memory.perms(offset, rem_size);

        if (perms[0] & PERM_CHUNK_START) == 0 {
            let vaddr = AddressSpace::Data(offset).encode();
            return Err(HeapError::NotAChunk(vaddr));
        }

        /* Get size of old chunk */
        let mut old_size = 0;
        let num_qwords = rem_size / 8;
        let arr = unsafe { std::mem::transmute::<*const u8, *const u64>(perms.as_ptr().add(1)) };
        let arr = unsafe { std::slice::from_raw_parts(arr, num_qwords) };
        let perm_mask = broadcast_perm::<u64>(PERM_CHUNK_END);

        for elem in arr {
            if (*elem & perm_mask) != 0 {
                break;
            }

            old_size += 8;
        }

        for perm in &perms[1 + old_size..] {
            if (*perm & PERM_CHUNK_END) != 0 {
                break;
            }

            old_size += 1;
        }

        /* Allocate a new chunk */
        let new_chunk = self.malloc(memory, new_size)?;

        /* Copy permissions and content */
        offset += 1;
        let copy_len = std::cmp::min(old_size, new_size);

        memory.perms_mut_raw(0, self.cursor).copy_within(offset..offset + copy_len, new_chunk);
        memory.content_mut_raw(0, self.cursor).copy_within(offset..offset + copy_len, new_chunk);

        /* Free the old chunk */
        self.free(memory, offset).unwrap();

        Ok(new_chunk)
    }

    fn parse_heap_chunk(&self, perms: &[u8], offset: usize) -> HeapChunk {
        let mut size = 0;

        for &perm in perms.iter().skip(1) {
            if (perm & PERM_CHUNK_END) != 0 {
                break;
            } else {
                size += 1;
            }
        }

        HeapChunk {
            addr: AddressSpace::Data(offset + 1).encode(),
            size,
        }
    }

    pub(crate) fn get_heap_chunk(&self, memory: &Memory, offset: usize) -> Result<HeapChunk, HeapError> {
        if offset >= self.cursor {
            let vaddr = AddressSpace::Data(offset).encode();
            return Err(HeapError::OutOfBounds(vaddr));
        }

        /* Check if offset refers to an actual chunk */
        let offset = offset.saturating_sub(1);
        let rem_size = self.cursor - offset;
        let perms = memory.perms(offset, rem_size);

        if (perms[0] & PERM_CHUNK_START) == 0 {
            let vaddr = AddressSpace::Data(offset).encode();
            return Err(HeapError::NotAChunk(vaddr));
        }

        Ok(self.parse_heap_chunk(perms, offset))
    }

    pub(crate) fn get_heap_chunks(&self, memory: &Memory) -> Vec<HeapChunk> {
        let mut ret = Vec::new();
        let mut offset = memory.heap();
        let perms = memory.perms(offset, self.cursor - offset);

        while offset < self.cursor {
            let perm = perms[offset];

            if (perm & PERM_CHUNK_START) != 0 {
                let chunk = self.parse_heap_chunk(&perms[offset..], offset);
                offset += chunk.size();
                ret.push(chunk);
            } else {
                offset += 1;
            }
        }

        ret
    }

    #[inline]
    pub(crate) fn has_mem_leaks(&self) -> bool {
        self.count > 0
    }

    #[inline]
    pub(crate) fn memory_usage(&self, memory: &Memory) -> usize {
        self.cursor - memory.heap()
    }

    pub(crate) fn reset_count(&mut self) {
        self.count = 0;
    }
}
