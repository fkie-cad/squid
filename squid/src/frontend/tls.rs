use std::{
    cmp::Ordering,
    collections::BTreeSet,
};

use goblin;
use paste::paste;

use crate::frontend::{
    chunk::{
        Chunk,
        ChunkContent,
    },
    error::LoaderError,
    fixedvec::FixedVec,
    idmap::{
        idmap_functions,
        HasId,
        HasIdMut,
        Id,
        IdMap,
        IdMapValues,
        IdMapValuesMut,
    },
    image::VAddr,
    perms::Perms,
    reloc::parse_relocations,
};

/// The offset into the TLS region
pub type TlsOffset = u64;

/// A ThreadLocal is a variable that occupies a certain number of bytes in the TLS area
#[derive(Debug, Hash)]
pub struct ThreadLocal {
    id: Id,
    public_names: BTreeSet<String>,
    private_names: BTreeSet<String>,
    offset: TlsOffset,
    size: usize,
    file_offset: Option<usize>,
    idmap: IdMap<Chunk>,
    cursor: usize,
    vaddr: VAddr,
}

impl ThreadLocal {
    fn new(offset: TlsOffset, size: usize, vaddr: VAddr) -> Self {
        Self {
            id: Id::default(),
            public_names: BTreeSet::new(),
            private_names: BTreeSet::new(),
            offset,
            size,
            file_offset: None,
            idmap: IdMap::new(),
            cursor: 0,
            vaddr,
        }
    }

    fn new_public(name: String, offset: TlsOffset, size: usize, vaddr: VAddr) -> Self {
        Self {
            id: Id::default(),
            public_names: {
                let mut set = BTreeSet::new();
                set.insert(name);
                set
            },
            private_names: BTreeSet::new(),
            offset,
            size,
            file_offset: None,
            idmap: IdMap::new(),
            cursor: 0,
            vaddr,
        }
    }

    fn new_private(name: String, offset: TlsOffset, size: usize, vaddr: VAddr) -> Self {
        Self {
            id: Id::default(),
            public_names: BTreeSet::new(),
            private_names: {
                let mut set = BTreeSet::new();
                set.insert(name);
                set
            },
            offset,
            size,
            file_offset: None,
            idmap: IdMap::new(),
            cursor: 0,
            vaddr,
        }
    }

    /// The public names of the thread local (from .dynsym)
    pub fn public_names(&self) -> &BTreeSet<String> {
        &self.public_names
    }

    /// The private names of the thread local (from .symtab)
    pub fn private_names(&self) -> &BTreeSet<String> {
        &self.private_names
    }

    /// The offset of this variable in the TLS area
    pub fn offset(&self) -> TlsOffset {
        self.offset
    }

    /// The size of the variabe
    pub fn size(&self) -> usize {
        self.size
    }

    /// The last index into the TLS area that this variable occupies (length - 1)
    pub fn last_offset(&self) -> TlsOffset {
        self.offset + self.size as TlsOffset - 1
    }

    /// The last address that this variable occupies
    pub fn last_addr(&self) -> VAddr {
        self.vaddr + self.size as VAddr - 1
    }

    /// Check whether this thread local contains the given offset
    pub fn contains_offset(&self, offset: TlsOffset) -> bool {
        self.offset <= offset && offset <= self.last_offset()
    }

    /// The virtual address of this thread local
    pub fn vaddr(&self) -> VAddr {
        self.vaddr
    }

    /// Change the offset of this thread local
    pub fn set_offset(&mut self, offset: TlsOffset) {
        self.offset = offset;
    }

    /// Change the size of this thread local
    pub fn set_size(&mut self, size: usize) {
        self.size = size;
    }

    /// Change the virtual address of this thread local
    pub fn set_vaddr(&mut self, vaddr: VAddr) {
        self.vaddr = vaddr;
    }
}

idmap_functions!(ThreadLocal, Chunk, chunk);

impl HasId for ThreadLocal {
    fn id(&self) -> Id {
        self.id
    }
}

impl HasIdMut for ThreadLocal {
    fn id_mut(&mut self) -> &mut Id {
        &mut self.id
    }
}

/// The Tls is the thread-local storage area that contains all the thread-local variables.
#[derive(Debug, Hash)]
pub struct Tls {
    idmap: IdMap<ThreadLocal>,
    cursor: usize,
}

impl Tls {
    pub(crate) fn new() -> Self {
        Self {
            idmap: IdMap::new(),
            cursor: 0,
        }
    }
}

idmap_functions!(Tls, ThreadLocal, thread_local);

pub(crate) struct InitImage {
    file_size: TlsOffset,
    mem_size: TlsOffset,
    offset: usize,
    vaddr: VAddr,
}

impl InitImage {
    pub(crate) fn new(elf: &goblin::elf::Elf) -> Result<Option<Self>, LoaderError> {
        let mut result = None;

        for ph in &elf.program_headers {
            if ph.p_type == goblin::elf::program_header::PT_TLS {
                if result.is_some() {
                    return Err(LoaderError::InvalidELF("Binary has multiple TLS initialization images".to_string()));
                }

                result = Some(InitImage {
                    file_size: ph.p_filesz as TlsOffset,
                    mem_size: ph.p_memsz as TlsOffset,
                    offset: ph.p_offset as usize,
                    vaddr: ph.p_vaddr as VAddr,
                });
            }
        }

        Ok(result)
    }
}

pub(crate) struct TlsParser {
    locals: Vec<ThreadLocal>,
}

impl TlsParser {
    pub(crate) fn parse(elf: &goblin::elf::Elf, content: &[u8]) -> Result<Tls, LoaderError> {
        /* Parse ELF */
        let mut builder = Self::new();

        if let Some(init_img) = InitImage::new(elf)? {
            builder.parse_symbols(elf, &init_img)?;
            builder.check_overlaps()?;
            builder.fill_gaps(&init_img);
            builder.split_sections(elf, &init_img);
            builder.adjust_file_offsets(&init_img);
            builder.create_chunks(elf, content)?;
            builder.verify(&init_img);
        }

        /* Build IdMap */
        let mut map = IdMap::new();

        for local in builder.locals {
            map.insert(local);
        }

        Ok(Tls {
            idmap: map,
            cursor: 0,
        })
    }

    fn new() -> Self {
        Self {
            locals: Vec::new(),
        }
    }

    fn verify(&self, img: &InitImage) {
        let mut offset_cursor = 0;

        for local in &self.locals {
            assert_eq!(offset_cursor, local.offset);
            offset_cursor += local.size as TlsOffset;

            let mut chunk_cursor = local.vaddr();
            for chunk in local.iter_chunks() {
                assert_eq!(chunk_cursor, chunk.vaddr());
                chunk_cursor += chunk.size() as VAddr;
            }

            assert_eq!(chunk_cursor, img.vaddr + local.offset as VAddr + local.size as VAddr);
        }

        assert_eq!(offset_cursor, img.mem_size);
    }

    fn create_chunks(&mut self, elf: &goblin::elf::Elf, content: &[u8]) -> Result<(), LoaderError> {
        let mut base_perms = Perms::default();
        base_perms.make_readable();
        base_perms.make_writable();

        for local in &mut self.locals {
            let mut chunks = Vec::<Chunk>::new();
            let parent_start = local.vaddr();
            let parent_size = local.size() as u64;

            /* First parse relocations inside the initialization image.
              Since we have strictly parsed all relocations before we can leave out
              a lot of checks here.
            */
            if local.file_offset.is_some() {
                for (rel, vaddr, size) in parse_relocations(elf, parent_start, parent_size)? {
                    let idx = chunks.binary_search_by(|x| if x.contains_address(vaddr) { Ordering::Equal } else { x.vaddr().cmp(&vaddr) });

                    match idx {
                        Ok(_) => unreachable!(),
                        Err(idx) => {
                            chunks.insert(idx, Chunk::new_pending(rel, vaddr, size));
                        },
                    }
                }
            }

            /* Then fill the chunk gaps */
            let mut cursor = parent_start;
            let mut i = 0;

            while i < chunks.len() {
                if cursor < chunks[i].vaddr() {
                    let chunk_len = (chunks[i].vaddr() - cursor) as usize;
                    let bytes = if let Some(mut offset) = local.file_offset {
                        offset += (cursor - parent_start) as usize;
                        FixedVec::lock(&content[offset..offset + chunk_len])
                    } else {
                        FixedVec::lock(vec![0; chunk_len])
                    };
                    let perms = FixedVec::lock(vec![base_perms; chunk_len]);

                    chunks.insert(
                        i,
                        Chunk::new_resolved(
                            ChunkContent::Data {
                                bytes,
                                perms,
                            },
                            cursor,
                            chunk_len,
                        ),
                    );
                }

                cursor += chunks[i].size() as VAddr;
                i += 1;
            }

            let parent_end = parent_start + parent_size;

            if cursor < parent_end {
                let chunk_len = (parent_end - cursor) as usize;
                let bytes = if let Some(mut offset) = local.file_offset {
                    offset += (cursor - parent_start) as usize;
                    FixedVec::lock(&content[offset..offset + chunk_len])
                } else {
                    FixedVec::lock(vec![0; chunk_len])
                };
                let perms = FixedVec::lock(vec![base_perms; chunk_len]);

                chunks.push(Chunk::new_resolved(
                    ChunkContent::Data {
                        bytes,
                        perms,
                    },
                    cursor,
                    chunk_len,
                ));
            }

            /* Build IdMap */
            let mut map = IdMap::new();

            for chunk in chunks {
                map.insert(chunk);
            }

            local.idmap = map;
        }

        Ok(())
    }

    fn split_sections(&mut self, elf: &goblin::elf::Elf, img: &InitImage) {
        for sh in &elf.section_headers {
            if (sh.sh_flags & goblin::elf::section_header::SHF_TLS as u64) != 0 {
                let section_addr = sh.sh_addr as VAddr;
                let section_offset = (section_addr - img.vaddr) as TlsOffset;
                let idx = self.locals.binary_search_by(|x| if x.contains_offset(section_offset) { Ordering::Equal } else { x.offset.cmp(&section_offset) });

                match idx {
                    Ok(idx) => {
                        let local = &mut self.locals[idx];
                        let delta = section_offset - local.offset;

                        if delta > 0 {
                            let end = local.last_offset() + 1;
                            local.size = delta as usize;
                            let new_local = ThreadLocal::new(section_offset, (end - section_offset) as usize, img.vaddr + section_offset);
                            self.locals.insert(idx + 1, new_local);
                        }
                    },
                    Err(_) => unreachable!(),
                }
            }
        }
    }

    fn adjust_file_offsets(&mut self, img: &InitImage) {
        for local in &mut self.locals {
            if local.offset < img.file_size {
                local.file_offset = Some(img.offset + local.offset as usize);
            } else {
                local.file_offset = None;
            }
        }
    }

    fn fill_gaps(&mut self, img: &InitImage) {
        let mut cursor = 0;
        let mut i = 0;

        while i < self.locals.len() {
            if cursor < self.locals[i].offset {
                let new_local = ThreadLocal::new(cursor, (self.locals[i].offset - cursor) as usize, img.vaddr + cursor);
                self.locals.insert(i, new_local);
            }

            cursor += self.locals[i].size as TlsOffset;
            i += 1;
        }

        if cursor < img.mem_size {
            let new_local = ThreadLocal::new(cursor, (img.mem_size - cursor) as usize, img.vaddr + cursor);
            self.locals.push(new_local);
        }
    }

    fn check_overlaps(&self) -> Result<(), LoaderError> {
        let mut cursor = 0;

        for local in &self.locals {
            if local.offset < cursor {
                return Err(LoaderError::InvalidELF(format!("Overlapping TLS symbol {:#x}", local.offset)));
            }

            cursor = local.last_offset() + 1;
        }

        Ok(())
    }

    fn parse_symbols(&mut self, elf: &goblin::elf::Elf, img: &InitImage) -> Result<(), LoaderError> {
        /* Parse globals */
        for symbol in elf.dynsyms.iter() {
            if symbol.st_type() == goblin::elf::sym::STT_TLS {
                let offset = symbol.st_value as TlsOffset;
                let size = symbol.st_size as usize;
                let name = elf.dynstrtab.get_at(symbol.st_name).unwrap();

                assert!(symbol.st_size > 0);

                match self.locate_local(offset) {
                    Ok(idx) => {
                        if self.locals[idx].size != size {
                            return Err(LoaderError::InvalidELF(format!("Overlapping TLS symbols {:#x} and {:#x}", offset, self.locals[idx].offset)));
                        } else {
                            self.locals[idx].public_names.insert(name.to_string());
                        }
                    },
                    Err(idx) => {
                        let new_local = ThreadLocal::new_public(name.to_string(), offset, size, img.vaddr + offset);
                        self.locals.insert(idx, new_local);
                    },
                }
            }
        }

        /* Parse locals */
        for symbol in elf.syms.iter() {
            if symbol.st_type() == goblin::elf::sym::STT_TLS {
                let offset = symbol.st_value as TlsOffset;
                let size = symbol.st_size as usize;
                let name = elf.strtab.get_at(symbol.st_name).unwrap();

                assert!(symbol.st_size > 0);

                match self.locate_local(offset) {
                    Ok(idx) => {
                        if self.locals[idx].size != size {
                            return Err(LoaderError::InvalidELF(format!("Overlapping TLS symbols {:#x} and {:#x}", offset, self.locals[idx].offset)));
                        } else {
                            self.locals[idx].private_names.insert(name.to_string());
                        }
                    },
                    Err(idx) => {
                        let new_local = ThreadLocal::new_private(name.to_string(), offset, size, img.vaddr + offset);
                        self.locals.insert(idx, new_local);
                    },
                }
            }
        }

        Ok(())
    }

    fn locate_local(&self, offset: TlsOffset) -> Result<usize, usize> {
        self.locals.binary_search_by(|x| x.offset.cmp(&offset))
    }
}
