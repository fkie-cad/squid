use std::collections::BTreeMap;

use rustc_hash::FxHashMap as HashMap;

use crate::{
    backends::clang::{
        perms,
        perms::convert_loader_perms,
        AddressSpace,
    },
    frontend::{
        ChunkContent,
        ProcessImage,
        VAddr,
    },
    runtime::SnapshotId,
};

pub(crate) const PAGE_SIZE: usize = 4096;
pub(crate) const SNAPSHOT_REGION_SIZE: usize = 1024;

#[inline]
fn idiv_ceil<const D: usize>(num: usize) -> usize {
    let mut quot = num / D;
    let rem = num % D;

    if rem != 0 {
        quot += 1;
    }

    quot
}

#[inline]
fn round_up<const C: usize>(num: usize) -> usize {
    let rem = num % C;

    if rem == 0 {
        num
    } else {
        num + C - rem
    }
}

pub(crate) struct Memory {
    /// `[content] [pad] [perms] [pad] [dirty bits] [dirty stack]`
    data: Vec<u8>,
    size: usize,
    offset_perms: usize,
    offset_dirty_bits: usize,
    offset_dirty_stack: usize,
    heap: usize,
    heap_end: usize,
    stack: usize,
    last_snapshot: SnapshotId,
    snapshots: HashMap<SnapshotId, Vec<u8>>,
}

impl Memory {
    pub(crate) fn new(image: &ProcessImage, org_globals_size: usize, org_heap_size: usize, org_stack_size: usize) -> Self {
        let globals_size = round_up::<PAGE_SIZE>(org_globals_size);
        let heap_size = round_up::<PAGE_SIZE>(org_heap_size);
        let stack_size = PAGE_SIZE + round_up::<PAGE_SIZE>(org_stack_size) + PAGE_SIZE;
        let total_size = globals_size + heap_size + stack_size;
        
        let num_regions = idiv_ceil::<SNAPSHOT_REGION_SIZE>(total_size);
        let dirty_bitmap_size = round_up::<8>(idiv_ceil::<8>(num_regions));
        let dirty_stack_size = 8 * (1 + dirty_bitmap_size * 8);

        let mut data = vec![0; 2 * total_size + dirty_bitmap_size + dirty_stack_size];
        let mut bytes_cursor = 0;
        let mut perms_cursor = total_size;

        /* Build globals */
        for elf in image.iter_elfs() {
            for section in elf.iter_sections() {
                if section.perms().is_executable() {
                    continue;
                }

                for symbol in section.iter_symbols() {
                    for chunk in symbol.iter_chunks() {
                        let ChunkContent::Data {
                            bytes,
                            perms,
                        } = chunk.content()
                        else {
                            unreachable!()
                        };

                        data[bytes_cursor..bytes_cursor + bytes.len()].copy_from_slice(&bytes[..]);
                        bytes_cursor += bytes.len();

                        for perm in &perms[..] {
                            data[perms_cursor] = convert_loader_perms(*perm);
                            perms_cursor += 1;
                        }
                    }
                }
            }
        }
        
        Self {
            data,
            size: total_size,
            offset_perms: total_size,
            offset_dirty_bits: 2 * total_size,
            offset_dirty_stack: 2 * total_size + dirty_bitmap_size,
            heap: globals_size,
            heap_end: globals_size + org_heap_size,
            stack: globals_size + heap_size,
            last_snapshot: SnapshotId::default(),
            snapshots: HashMap::default(),
        }
    }

    pub(crate) fn offset_perms(&self) -> usize {
        self.offset_perms
    }

    pub(crate) fn offset_dirty_bits(&self) -> usize {
        self.offset_dirty_bits
    }

    pub(crate) fn offset_dirty_stack(&self) -> usize {
        self.offset_dirty_stack
    }

    pub(crate) fn mark_dirty(&mut self, start: usize, len: usize) {
        let first = start / SNAPSHOT_REGION_SIZE;
        let last = (start + len.saturating_sub(1)) / SNAPSHOT_REGION_SIZE;

        for region in first..=last {
            let idx = region / 8;
            let bit = region % 8;

            let mask = 1 << bit;
            let byte = unsafe { self.data.get_unchecked_mut(self.offset_dirty_bits + idx) };

            if *byte & mask == 0 {
                *byte |= mask;

                let stack = unsafe { std::mem::transmute::<*mut u8, *mut usize>(self.data.as_mut_ptr().add(self.offset_dirty_stack)) };
                let stack_size = unsafe { *stack } + 1;

                unsafe {
                    *stack.add(stack_size) = region;
                    *stack = stack_size;
                }
            }
        }
    }

    #[inline]
    pub(crate) fn is_in_bounds(&self, start: usize, len: usize) -> bool {
        start.saturating_add(len) <= self.size
    }

    #[inline]
    pub(crate) fn content(&self, start: usize, len: usize) -> &[u8] {
        debug_assert!(self.is_in_bounds(start, len));
        unsafe { self.data.get_unchecked(start..start + len) }
    }

    #[inline]
    pub(crate) fn content_mut(&mut self, start: usize, len: usize) -> &mut [u8] {
        debug_assert!(self.is_in_bounds(start, len));
        self.mark_dirty(start, len);
        unsafe { self.data.get_unchecked_mut(start..start + len) }
    }

    #[inline]
    pub(crate) fn content_mut_raw(&mut self, start: usize, len: usize) -> &mut [u8] {
        debug_assert!(self.is_in_bounds(start, len));
        unsafe { self.data.get_unchecked_mut(start..start + len) }
    }

    #[inline]
    pub(crate) fn perms(&self, start: usize, len: usize) -> &[u8] {
        debug_assert!(self.is_in_bounds(start, len));
        unsafe { self.data.get_unchecked(self.offset_perms + start..self.offset_perms + start + len) }
    }

    #[inline]
    pub(crate) fn perms_mut(&mut self, start: usize, len: usize) -> &mut [u8] {
        debug_assert!(self.is_in_bounds(start, len));
        self.mark_dirty(start, len);
        unsafe { self.data.get_unchecked_mut(self.offset_perms + start..self.offset_perms + start + len) }
    }

    #[inline]
    pub(crate) fn perms_mut_raw(&mut self, start: usize, len: usize) -> &mut [u8] {
        debug_assert!(self.is_in_bounds(start, len));
        unsafe { self.data.get_unchecked_mut(self.offset_perms + start..self.offset_perms + start + len) }
    }

    pub(crate) fn take_snapshot(&mut self, id: SnapshotId) {
        self.snapshots.insert(id, self.data[0..self.offset_dirty_bits].to_vec());
    }

    pub(crate) fn restore_snapshot_unchecked(&mut self, id: SnapshotId) {
        let snapshot = self.snapshots.get(&id);
        let snapshot = unsafe { snapshot.unwrap_unchecked() };

        if self.last_snapshot == id {
            /* Do a fast reset with dirty bit mechanics */
            let stack = unsafe { std::mem::transmute::<*const u8, *const usize>(self.data.as_ptr().add(self.offset_dirty_stack)) };
            let stack_size = unsafe { *stack };

            for i in 0..stack_size {
                let region = unsafe { *stack.add(1 + i) };
                let mut bytes_start = region * SNAPSHOT_REGION_SIZE;
                debug_assert!(bytes_start < self.offset_perms);
                debug_assert!(bytes_start + SNAPSHOT_REGION_SIZE <= self.offset_perms);

                unsafe {
                    let dst = self.data.as_mut_ptr().add(bytes_start);
                    let src = snapshot.as_ptr().add(bytes_start);
                    std::ptr::copy_nonoverlapping(src, dst, SNAPSHOT_REGION_SIZE);
                }

                bytes_start += self.offset_perms;
                debug_assert!(bytes_start < self.offset_dirty_bits);
                debug_assert!(bytes_start + SNAPSHOT_REGION_SIZE <= self.offset_dirty_bits);

                unsafe {
                    let dst = self.data.as_mut_ptr().add(bytes_start);
                    let src = snapshot.as_ptr().add(bytes_start);
                    std::ptr::copy_nonoverlapping(src, dst, SNAPSHOT_REGION_SIZE);
                }
            }
        } else {
            /* Do a slow reset because dirty bits produce invalid results here */
            unsafe {
                let dst = self.data.as_mut_ptr();
                let src = snapshot.as_ptr();
                std::ptr::copy_nonoverlapping(src, dst, self.offset_dirty_bits);
            }

            self.last_snapshot = id;
        }

        /* Clear dirty bitmap and stack */
        for byte in unsafe { self.data.get_unchecked_mut(self.offset_dirty_bits..self.offset_dirty_stack + 8) } {
            *byte = 0;
        }
    }

    pub(crate) fn delete_snapshot_unchecked(&mut self, id: SnapshotId) {
        self.snapshots.remove(&id);
    }

    pub(crate) fn size(&self) -> usize {
        self.size
    }

    pub(crate) fn raw_pointer(&mut self) -> *mut u8 {
        self.data.as_mut_ptr()
    }

    pub(crate) fn clear_dirty_stack(&mut self) {
        for byte in unsafe { self.data.get_unchecked_mut(self.offset_dirty_bits..self.offset_dirty_stack + 8) } {
            *byte = 0;
        }
    }
    
    pub(crate) fn stack(&self) -> usize {
        self.stack
    }
    
    pub(crate) fn heap(&self) -> usize {
        self.heap
    }
    
    pub(crate) fn heap_end(&self) -> usize {
        self.heap_end
    }
}

fn store_slice(memory: &mut Memory, sp: usize, slice: &[u8]) -> Option<()> {
    if sp < memory.stack() {
        return None;
    }

    for perm_byte in memory.perms_mut_raw(sp, slice.len()) {
        *perm_byte = perms::PERM_READ | perms::PERM_WRITE;
    }

    memory.content_mut_raw(sp, slice.len()).copy_from_slice(slice);

    Some(())
}

pub(crate) fn populate_stack(memory: &mut Memory, args: &[String], env: &BTreeMap<String, String>) -> Option<VAddr> {
    let null = 0 as VAddr;
    let mut env_addresses = Vec::new();
    let mut arg_addresses = Vec::new();
    let mut sp = memory.size().checked_sub(PAGE_SIZE)?;

    /* Store environment strings */
    for (key, value) in env {
        let key = key.as_bytes();
        let value = value.as_bytes();
        let total_len = key.len() + 1 + value.len() + 1;

        // Redzone
        sp = sp.checked_sub(total_len)?;

        // Content
        sp = sp.checked_sub(total_len)?;

        let mut cursor = sp;
        store_slice(memory, cursor, key)?;
        cursor += key.len();
        store_slice(memory, cursor, &[b'='])?;
        cursor += 1;
        store_slice(memory, cursor, value)?;
        cursor += value.len();
        store_slice(memory, cursor, &[0])?;

        env_addresses.push(sp);
    }

    /* Store arguments */
    for arg in args {
        let arg = arg.as_bytes();
        let total_len = arg.len() + 1;

        // Redzone
        sp = sp.checked_sub(total_len)?;

        // Content
        sp = sp.checked_sub(total_len)?;

        store_slice(memory, sp, arg)?;
        store_slice(memory, sp + arg.len(), &[0])?;

        arg_addresses.push(sp);
    }

    /* Align to 16 bytes */
    let pad = sp.checked_sub(sp & !0xF)?;
    sp = sp.checked_sub(pad)?;

    if (args.len() + 1 + env.len() + 1) % 2 == 0 {
        sp = sp.checked_sub(8)?;
    }

    /* Empty aux vector */
    sp = sp.checked_sub(16)?;

    sp = sp.checked_sub(16)?;
    store_slice(memory, sp, &null.to_le_bytes())?;
    store_slice(memory, sp + 8, &null.to_le_bytes())?;

    /* Environment */
    sp = sp.checked_sub(8)?;
    store_slice(memory, sp, &null.to_le_bytes())?;

    for addr in env_addresses {
        let addr = AddressSpace::Data(addr).encode().to_le_bytes();
        sp = sp.checked_sub(addr.len())?;
        store_slice(memory, sp, &addr)?;
    }

    /* Arguments */
    sp = sp.checked_sub(8)?;
    store_slice(memory, sp, &null.to_le_bytes())?;

    for addr in arg_addresses.iter().rev() {
        let addr = AddressSpace::Data(*addr).encode().to_le_bytes();
        sp = sp.checked_sub(addr.len())?;
        store_slice(memory, sp, &addr)?;
    }

    /* Argument count */
    sp = sp.checked_sub(8)?;
    store_slice(memory, sp, &args.len().to_le_bytes())?;

    /* Mark space below as readable and writable */
    let start = memory.stack();
    let size = sp - start;
    
    for byte in memory.perms_mut_raw(start, size) {
        *byte = perms::PERM_READ | perms::PERM_WRITE | perms::PERM_UNINIT;
    }

    Some(AddressSpace::Data(sp).encode())
}

#[cfg(test)]
mod tests {
    /*
    use super::*;


    #[test]
    fn test_snapshots() {
        let mem_size = 1024 * 1024;
        let mut memory = Memory::new_uninit(mem_size, 0);

        /* Test stack and bitmap */
        memory.dump_stack();

        memory.content_mut(0, 1).unwrap();
        memory.dump_stack();

        memory.perms_mut(SNAPSHOT_REGION_SIZE, 1).unwrap();
        memory.dump_stack();

        memory.content_mut(0, 1).unwrap();
        memory.dump_stack();

        memory.take_snapshot(0);
        assert!( memory.restore_snapshot(0) );
        memory.dump_stack();

        for perm in memory.perms_mut(mem_size - 2, 1).unwrap() {
            *perm = 7;
        }
        memory.dump_stack();
        assert!( memory.restore_snapshot(0) );
        for perm in memory.perms(mem_size - 3, 3).unwrap() {
            assert_eq!(*perm, 0);
        }

        for byte in memory.content_mut(0, mem_size).unwrap() {
            *byte = 123;
        }
        for byte in memory.perms_mut(0, mem_size).unwrap() {
            *byte = 234;
        }
        memory.dump_stack();
        memory.take_snapshot(1);
        assert!( memory.restore_snapshot(1) );
        for byte in memory.content(0, mem_size).unwrap() {
            assert_eq!(*byte, 123);
        }
        for byte in memory.perms(0, mem_size).unwrap() {
            assert_eq!(*byte, 234);
        }
    }
    */

    /*
    /// Results for 64MiB and 10k resets:
    ///     Dirty bits full reset: 157.50s
    ///     Dirty bits half reset: 124.64s
    ///     Dirty bits quarter reset: 60.41s
    ///     Dirty bits eighth reset: 28.83s
    #[test]
    fn bench_snapshots() {
        let mem_size = 64 * 1024 * 1024;
        let mut memory = Memory::new_uninit(mem_size, 7);
        memory.take_snapshot(0);

        for _ in 0..10_000 {
            assert!( memory.content_mut(0, mem_size / 8).is_some() );
            assert!( memory.restore_snapshot(0) );
        }
    }
    */

    /*
    #[test]
    fn test_stack() {
        let mut memory = Memory::new_uninit(PAGE_SIZE * 2, 0);
        let args = [
            "test123".to_string(),
        ];
        let mut env = BTreeMap::new();
        env.insert("TEST".to_string(), "123".to_string());

        let sp = populate_stack(&mut memory, &args, &env).unwrap();
        println!("sp = {:#x}", sp);

        let AddressSpace::Stack(offset) = AddressSpace::decode(sp) else { unreachable!() };

        let content = memory.content(offset, memory.size() - offset).unwrap();
        let perms = memory.perms(offset, memory.size() - offset).unwrap();

        for (i, (perm, byte)) in perms.iter().zip(content.iter()).enumerate() {
            println!("[{}]:", i);
            println!(" perm: {:04b}", *perm);
            println!(" byte: {:02x}", *byte);
            println!();
        }
    }
    */
}
