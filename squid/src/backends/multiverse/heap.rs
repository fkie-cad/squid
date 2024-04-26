use rustc_hash::FxHashMap;
use thiserror::Error;

use crate::{
    backends::multiverse::{
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
    count: usize,
    last_size: usize,
    snapshots: FxHashMap<SnapshotId, SnapshotData>,
}

impl Heap {
    pub(crate) fn new() -> Self {
        Self {
            cursor: 0,
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

    pub(crate) fn malloc(&mut self, memory: &mut Memory, size: usize) -> Result<usize, HeapError> {
        if size == 0 {
            return Err(HeapError::EmptyAllocation);
        }

        let mut left_redzone_size = size.saturating_sub(self.last_size);
        left_redzone_size += 16 - ((self.cursor + left_redzone_size) & 0xF);
        let memory_usage = left_redzone_size.saturating_add(size.saturating_mul(2));

        if !memory.is_in_bounds(self.cursor, memory_usage) {
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
            let vaddr = AddressSpace::Heap(offset).encode();
            return Err(HeapError::OutOfBounds(vaddr));
        }

        let offset = offset.saturating_sub(1);
        let rem_size = self.cursor - offset;

        /* Check if we are freeing an actual chunk */
        let perms = memory.perms_mut_raw(offset, rem_size);

        if (perms[0] & PERM_CHUNK_START) == 0 {
            let vaddr = AddressSpace::Heap(offset).encode();
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
            let vaddr = AddressSpace::Heap(offset).encode();
            return Err(HeapError::OutOfBounds(vaddr));
        }

        /* Check if we are reallocating an actual chunk */
        let mut offset = offset.saturating_sub(1);
        let rem_size = self.cursor - offset;
        let perms = memory.perms(offset, rem_size);

        if (perms[0] & PERM_CHUNK_START) == 0 {
            let vaddr = AddressSpace::Heap(offset).encode();
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
            addr: AddressSpace::Heap(offset + 1).encode(),
            size,
        }
    }

    pub(crate) fn get_heap_chunk(&self, memory: &Memory, offset: usize) -> Result<HeapChunk, HeapError> {
        if offset >= self.cursor {
            let vaddr = AddressSpace::Heap(offset).encode();
            return Err(HeapError::OutOfBounds(vaddr));
        }

        /* Check if offset refers to an actual chunk */
        let offset = offset.saturating_sub(1);
        let rem_size = self.cursor - offset;
        let perms = memory.perms(offset, rem_size);

        if (perms[0] & PERM_CHUNK_START) == 0 {
            let vaddr = AddressSpace::Heap(offset).encode();
            return Err(HeapError::NotAChunk(vaddr));
        }

        Ok(self.parse_heap_chunk(perms, offset))
    }

    pub(crate) fn get_heap_chunks(&self, memory: &Memory) -> Vec<HeapChunk> {
        let mut ret = Vec::new();
        let mut offset = 0;
        let perms = memory.perms(0, self.cursor);

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
    pub(crate) fn memory_usage(&self) -> usize {
        self.cursor
    }

    pub(crate) fn reset_count(&mut self) {
        self.count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal() {
        let mut mem = Memory::new_uninit(900, PERM_NONE);
        let mut mgr = Heap::new();

        assert!(mgr.malloc(&mut mem, 0).is_err());
        assert!(mgr.malloc(&mut mem, 301).is_err());

        let offset = mgr.malloc(&mut mem, 300).unwrap();
        assert_eq!(offset, 300);

        assert!(mgr.malloc(&mut mem, 1).is_err());
    }

    #[test]
    fn overflow() {
        let mut mem = Memory::new_uninit(900, PERM_NONE);
        let mut mgr = Heap::new();
        assert!(mgr.malloc(&mut mem, 12297829382473034410).is_err());
    }

    #[test]
    fn empty() {
        let mut mem = Memory::new_uninit(0, PERM_NONE);
        let mut mgr = Heap::new();
        assert!(mgr.malloc(&mut mem, 1).is_err());
    }

    #[test]
    fn double_free() {
        let mut mem = Memory::new_uninit(900, PERM_NONE);
        let mut mgr = Heap::new();

        let offset = mgr.malloc(&mut mem, 20).unwrap();
        assert_eq!(offset, 20);

        assert!(mgr.free(&mut mem, offset + 1).is_err());

        mgr.free(&mut mem, offset).unwrap();

        assert!(mgr.free(&mut mem, offset).is_err());
    }

    #[test]
    fn chunks() {
        let mut mem = Memory::new_uninit(900, PERM_NONE);
        let mut mgr = Heap::new();

        let a = mgr.malloc(&mut mem, 1).unwrap();
        let b = mgr.malloc(&mut mem, 2).unwrap();
        let c = mgr.malloc(&mut mem, 3).unwrap();
        let d = mgr.malloc(&mut mem, 100).unwrap();

        for byte in mem.perms_mut(d + 1, 100 - 2) {
            *byte = 0;
        }

        println!("{:#?}", mgr.get_heap_chunks(&mem));

        mgr.free(&mut mem, a).unwrap();
        mgr.free(&mut mem, b).unwrap();
        mgr.free(&mut mem, c).unwrap();

        println!("{:#?}", mgr.get_heap_chunks(&mem));

        mgr.free(&mut mem, d).unwrap();

        println!("{:#?}", mgr.get_heap_chunks(&mem));
    }

    #[test]
    fn bench_heap_1() {
        let mut mem = Memory::new_uninit(64 * 1024 * 1024, PERM_NONE);
        let mut mgr = Heap::new();

        mem.take_snapshot(0);
        mgr.take_snapshot(0);

        let mut trials = 0;
        let start = std::time::Instant::now();

        loop {
            trials += 1;

            if (trials % (1 << 5)) == 0 {
                let duration = (std::time::Instant::now() - start).as_secs_f64();
                println!("trials/s >= {}", trials as f64 / duration);
            }

            let offset = mgr.malloc(&mut mem, 10 * 1024 * 1024).unwrap();
            mgr.free(&mut mem, offset).unwrap();

            mem.restore_snapshot_unchecked(0);
            mgr.restore_snapshot_unchecked(0);
        }
    }

    #[test]
    fn test_byte_level_permissions() {
        let mut mem = Memory::new_uninit(64 * 1024 * 1024, PERM_NONE);
        let mut mgr = Heap::new();

        let chunk_len = 3 * 1024 * 1024 + 23;

        let offset = mgr.malloc(&mut mem, chunk_len).unwrap();

        for perm in mem.perms(offset, chunk_len) {
            assert_eq!(*perm, PERM_READ | PERM_WRITE | PERM_UNINIT);
        }

        assert_eq!(mem.perms(offset - 1, 1)[0], PERM_CHUNK_START);
        assert_eq!(mem.perms(offset + chunk_len, 1)[0], PERM_CHUNK_END);

        mgr.free(&mut mem, offset).unwrap();

        for perm in mem.perms(offset, chunk_len) {
            assert_eq!(*perm, 0);
        }
    }

    #[test]
    fn test_realloc() {
        let mut mem = Memory::new_uninit(64 * 1024 * 1024, PERM_NONE);
        let mut mgr = Heap::new();

        let a = mgr.malloc(&mut mem, 512).unwrap();
        mem.content_mut(a, 4).copy_from_slice(b"AAAA");

        mem.take_snapshot(0);
        mgr.take_snapshot(0);

        let b = mgr.realloc(&mut mem, a, 3).unwrap();
        assert_eq!(mem.content(b, 3 + 1), b"AAA\x00");
        assert_eq!(mem.perms(a, 3), b"\x00\x00\x00");

        mem.restore_snapshot_unchecked(0);
        mgr.restore_snapshot_unchecked(0);

        assert_eq!(mem.content(a, 3 + 1), b"AAAA");
        assert_eq!(mem.content(b, 3), b"\x00\x00\x00");
    }
}
