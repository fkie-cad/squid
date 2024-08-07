use std::{
    cmp::Ordering,
    fmt::{
        Debug,
        Formatter,
    },
};

use goblin;

use crate::{
    event::EventPool,
    frontend::{
        ao::{
            CFGError,
            Function,
            Lifter,
            CFG,
        },
        error::LoaderError,
        fixedvec::FixedVec,
        idmap::{
            HasId,
            HasIdMut,
            Id,
            IdMap,
        },
        image::VAddr,
        perms::Perms,
        pointer::Pointer,
        reloc::{
            parse_relocations,
            Relocation,
        },
        section::Section,
        symbol::Symbol,
    },
    listing::ListingManager,
    riscv::{
        instr::{
            decode,
            InstructionSet,
            RV32I,
        },
        register::GpRegister,
    },
};

/// The ChunkContent determines how the contents of a [`Chunk`] shall be interpreted.
/// This can either as code, data or as a pointer.
#[derive(Hash)]
pub enum ChunkContent {
    /// This chunk holds executable RISC-V code that was lifted into the IR
    Code(Function),

    /// This chunk contains data with the given permissions
    Data {
        /// The content of the chunk
        bytes: FixedVec<u8>,

        /// Byte-level permissions for every byte of the content
        perms: FixedVec<Perms>,
    },

    /// This chunk contains a pointer
    Pointer(Pointer),
}

impl Debug for ChunkContent {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ChunkContent::Code(_) => write!(f, "Code"),
            ChunkContent::Data {
                ..
            } => write!(f, "Data"),
            ChunkContent::Pointer(_) => write!(f, "Pointer"),
        }
    }
}

#[derive(Debug, Hash)]
enum Stage {
    Pending(Relocation),
    Resolved(ChunkContent),
}

/// Chunks are the leafs of the ProcessImage and they contain the actual data of an ELF file.
/// How the data is interpreted is determined by the [`ChunkContent`].
#[derive(Debug, Hash)]
pub struct Chunk {
    id: Id,
    stage: Stage,
    vaddr: VAddr,
    size: usize,
}

impl Chunk {
    pub(crate) fn new_pending(rel: Relocation, vaddr: VAddr, size: usize) -> Self {
        Self {
            id: Id::default(),
            stage: Stage::Pending(rel),
            vaddr,
            size,
        }
    }

    pub(crate) fn new_resolved(content: ChunkContent, vaddr: VAddr, size: usize) -> Self {
        Self {
            id: Id::default(),
            stage: Stage::Resolved(content),
            vaddr,
            size,
        }
    }

    pub(crate) fn pending(&self) -> Option<&Relocation> {
        match &self.stage {
            Stage::Pending(rel) => Some(rel),
            Stage::Resolved(_) => None,
        }
    }

    pub(crate) fn resolve(&mut self, pointer: Pointer) {
        self.stage = Stage::Resolved(ChunkContent::Pointer(pointer));
    }

    /// Access the content of this chunk
    pub fn content(&self) -> &ChunkContent {
        match &self.stage {
            Stage::Pending(_) => unreachable!(),
            Stage::Resolved(content) => content,
        }
    }

    /// Access the content of this chunk
    pub fn content_mut(&mut self) -> &mut ChunkContent {
        match &mut self.stage {
            Stage::Pending(_) => unreachable!(),
            Stage::Resolved(content) => content,
        }
    }

    /// Get the virtual address of this chunk
    pub fn vaddr(&self) -> VAddr {
        self.vaddr
    }

    /// Get the size of ths chunk
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get the last virtual address that this chunk occupies (size - 1)
    pub fn last_addr(&self) -> VAddr {
        self.vaddr + self.size as VAddr - 1
    }

    /// Check whether this chunk contains the given address
    pub fn contains_address(&self, vaddr: VAddr) -> bool {
        self.vaddr <= vaddr && vaddr <= self.last_addr()
    }

    /// Change the size of this chunk
    pub fn set_size(&mut self, size: usize) {
        self.size = size;
    }

    /// Change the virtual address of this chunk
    pub fn set_vaddr(&mut self, vaddr: VAddr) {
        self.vaddr = vaddr;
    }

    /// Change the content of this chunk
    pub fn set_content(&mut self, content: ChunkContent) {
        self.stage = Stage::Resolved(content);
    }

    /// Create a [`ChunkBuilder`] that can create Chunks from scratch
    pub fn builder() -> ChunkBuilder {
        ChunkBuilder {
            content: None,
            size: None,
            vaddr: 0,
        }
    }
}

impl HasId for Chunk {
    fn id(&self) -> Id {
        self.id
    }
}

impl HasIdMut for Chunk {
    fn id_mut(&mut self) -> &mut Id {
        &mut self.id
    }
}

/// The ChunkBuilder can create [`Chunk`]s from scratch
pub struct ChunkBuilder {
    content: Option<ChunkContent>,
    size: Option<usize>,
    vaddr: VAddr,
}

impl ChunkBuilder {
    /// Set the content of the chunk to be code
    pub fn code(mut self, cfg: CFG) -> Result<Self, CFGError> {
        let perfect = cfg.verify()?;
        self.content = Some(ChunkContent::Code(Function::new(cfg, perfect)));
        Ok(self)
    }

    /// Set the content of the chunk to be data
    pub fn initialized_data<D: Into<Vec<u8>>, P: Into<Vec<Perms>>>(mut self, data: D, perms: P) -> Self {
        let bytes = FixedVec::lock(data);
        
        if self.size.is_none() {
            self.size = Some(bytes.len());
        }
        
        self.content = Some(ChunkContent::Data {
            bytes,
            perms: FixedVec::lock(perms),
        });
        self
    }

    /// Set the content of the chunk to be uninitialized data.
    /// Uninitialized means that the bytes will be zero.
    pub fn uninitialized_data(mut self, size: usize, perms: Perms) -> Self {
        if self.size.is_none() {
            self.size = Some(size);
        }
        
        self.content = Some(ChunkContent::Data {
            bytes: FixedVec::lock(vec![0; size]),
            perms: FixedVec::lock(vec![perms; size]),
        });
        self
    }

    /// Set the content of this chunk to be a symbolic pointer
    pub fn pointer(mut self, pointer: Pointer) -> Self {
        self.size = Some(8);
        self.content = Some(ChunkContent::Pointer(pointer));
        self
    }

    /// Set the virtual address of this chunk
    pub fn vaddr(mut self, vaddr: VAddr) -> Self {
        self.vaddr = vaddr;
        self
    }

    /// Set the size of this chunk
    pub fn size(mut self, size: usize) -> Self {
        self.size = Some(size);
        self
    }

    /// Create a [`Chunk`] from the current configuration
    pub fn build(self) -> Result<Chunk, &'static str> {
        let content = self.content.ok_or("Chunk content was not set")?;
        let size = self.size.ok_or("Chunk size was not set")?;
        Ok(Chunk::new_resolved(content, self.vaddr, size))
    }
}

pub(crate) struct ChunkParser {
    chunks: Vec<Chunk>,
}

impl ChunkParser {
    pub(crate) fn parse(
        elf: &goblin::elf::Elf,
        parent: &Symbol,
        grandparent: &Section,
        content: &[u8],
        listing: &ListingManager,
        event_pool: &mut EventPool,
    ) -> Result<IdMap<Chunk>, LoaderError> {
        /* Build chunks */
        let mut builder = Self::new();

        if grandparent.offset().is_some() {
            builder.load_relocations(elf, parent)?;
            builder.check_overlaps(parent)?;
        }

        if parent.private_name(".plt").is_some() {
            builder.parse_plt(parent, grandparent, content, event_pool)?;
        } else {
            builder.fill_gaps(parent, grandparent, content, listing, event_pool)?;
        }

        builder.verify(parent);

        /* Create IdMap */
        let mut map = IdMap::new();

        for chunk in builder.chunks {
            map.insert(chunk);
        }

        Ok(map)
    }

    fn new() -> Self {
        Self {
            chunks: Vec::new(),
        }
    }

    fn verify(&self, parent: &Symbol) {
        let mut cursor = parent.vaddr();

        for chunk in &self.chunks {
            assert_eq!(chunk.vaddr, cursor);
            cursor += chunk.size as VAddr;
        }

        assert_eq!(cursor, parent.last_addr() + 1);
    }

    fn parse_plt(
        &mut self,
        parent: &Symbol,
        grandparent: &Section,
        content: &[u8],
        event_pool: &mut EventPool,
    ) -> Result<(), LoaderError> {
        if let Some(mut file_offset) = grandparent.offset() {
            assert!(self.chunks.is_empty());

            file_offset += (parent.vaddr() - grandparent.vaddr()) as usize;
            let instructions = &content[file_offset..file_offset + parent.size()];
            assert_eq!(instructions.len() % 4, 0);

            /* Parse initial plt code */
            let mut i = 0;
            while i < instructions.len() {
                if let InstructionSet::RV32I(RV32I::JALR(args)) = decode(&instructions[i..i + 4]) {
                    assert!(args.rs1 == GpRegister::t3 as usize);
                    assert_eq!(i, 7 * 4);
                    i += 4;
                    break;
                }

                i += 4;
            }

            let func =
                Lifter::lift(parent.vaddr(), grandparent.last_addr() + 1, &instructions[0..i], None, event_pool)?;
            let content = ChunkContent::Code(func);
            self.chunks.push(Chunk::new_resolved(content, parent.vaddr(), i));

            /* Parse individual PLT entries */
            while i < instructions.len() {
                let start_entry = i;
                let mut end_entry = start_entry;

                while end_entry < instructions.len() {
                    if let InstructionSet::RV32I(RV32I::ADDI(args)) = decode(&instructions[end_entry..end_entry + 4]) {
                        assert_eq!(args.rd, GpRegister::zero as usize);
                        assert_eq!(args.rs1, GpRegister::zero as usize);
                        assert_eq!(args.imm, 0);
                        assert_eq!(end_entry - start_entry, 3 * 4);
                        end_entry += 4;
                        break;
                    }

                    end_entry += 4;
                }

                assert!(end_entry > start_entry);

                let func = Lifter::lift(
                    parent.vaddr() + start_entry as VAddr,
                    grandparent.last_addr() + 1,
                    &instructions[start_entry..end_entry],
                    None,
                    event_pool,
                )?;
                let content = ChunkContent::Code(func);
                self.chunks.push(Chunk::new_resolved(
                    content,
                    parent.vaddr() + start_entry as VAddr,
                    end_entry - start_entry,
                ));

                i = end_entry;
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn parse_content(
        &self,
        vaddr: VAddr,
        size: usize,
        parent: &Symbol,
        grandparent: &Section,
        content: &[u8],
        listing: &ListingManager,
        event_pool: &mut EventPool,
    ) -> Result<ChunkContent, LoaderError> {
        if grandparent.perms().is_executable() {
            let offset = grandparent.offset().unwrap() + (vaddr - grandparent.vaddr()) as usize;
            let func = listing.lookup_symbol(parent)?;
            let func =
                Lifter::lift(vaddr, grandparent.last_addr() + 1, &content[offset..offset + size], func, event_pool)?;
            Ok(ChunkContent::Code(func))
        } else if let Some(mut offset) = grandparent.offset() {
            offset += (vaddr - grandparent.vaddr()) as usize;
            Ok(ChunkContent::Data {
                bytes: FixedVec::lock(&content[offset..offset + size]),
                perms: FixedVec::lock(vec![grandparent.perms(); size]),
            })
        } else {
            Ok(ChunkContent::Data {
                bytes: FixedVec::lock(vec![0; size]),
                perms: FixedVec::lock(vec![grandparent.perms(); size]),
            })
        }
    }

    fn fill_gaps(
        &mut self,
        parent: &Symbol,
        grandparent: &Section,
        content: &[u8],
        listing: &ListingManager,
        event_pool: &mut EventPool,
    ) -> Result<(), LoaderError> {
        if grandparent.perms().is_executable() && !self.chunks.is_empty() {
            return Err(LoaderError::InvalidELF("Binary has relocations in executable section".to_string()));
        }

        let mut cursor = parent.vaddr();
        let mut i = 0;

        while i < self.chunks.len() {
            let chunk = &self.chunks[i];

            if cursor < chunk.vaddr {
                let size = (chunk.vaddr - cursor) as usize;
                let content = self.parse_content(cursor, size, parent, grandparent, content, listing, event_pool)?;
                self.chunks.insert(i, Chunk::new_resolved(content, cursor, size));
            }

            cursor += self.chunks[i].size as VAddr;
            i += 1;
        }

        let symbol_end = parent.last_addr() + 1;

        if cursor < symbol_end {
            let size = (symbol_end - cursor) as usize;
            let content = self.parse_content(cursor, size, parent, grandparent, content, listing, event_pool)?;
            self.chunks.push(Chunk::new_resolved(content, cursor, size));
        }

        Ok(())
    }

    fn check_overlaps(&self, parent: &Symbol) -> Result<(), LoaderError> {
        let mut cursor = parent.vaddr();

        for chunk in &self.chunks {
            if chunk.vaddr < cursor {
                return Err(LoaderError::InvalidELF(format!("Overlapping chunks at {:#x}", chunk.vaddr)));
            }

            cursor = chunk.last_addr() + 1;
        }

        Ok(())
    }

    fn load_relocations(&mut self, elf: &goblin::elf::Elf, parent: &Symbol) -> Result<(), LoaderError> {
        for (rel, vaddr, size) in parse_relocations(elf, parent.vaddr(), parent.size() as u64)? {
            let vaddr = vaddr as VAddr;

            match self.locate_chunk(vaddr) {
                Ok(_) => return Err(LoaderError::InvalidELF(format!("Overlapping relocations at {:#x}", vaddr))),
                Err(idx) => self.chunks.insert(idx, Chunk::new_pending(rel, vaddr, size)),
            }
        }

        Ok(())
    }

    fn locate_chunk(&self, vaddr: VAddr) -> Result<usize, usize> {
        self.chunks.binary_search_by(|x| if x.contains_address(vaddr) { Ordering::Equal } else { x.vaddr.cmp(&vaddr) })
    }
}
