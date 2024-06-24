use std::cmp::Ordering;

use goblin;
use paste::paste;

use crate::{
    event::EventPool,
    frontend::{
        error::LoaderError,
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
        symbol::{
            Symbol,
            SymbolParser,
        },
    },
    listing::ListingManager,
};

/// A Section is consecutive group of symbols that share the same permissions
#[derive(Debug, Hash)]
pub struct Section {
    id: Id,
    perms: Perms,
    vaddr: VAddr,
    offset: Option<usize>,
    size: usize,
    idmap: IdMap<Symbol>,
    cursor: usize,
}

impl Section {
    pub(crate) fn new(perms: Perms, vaddr: VAddr, offset: Option<usize>, size: usize) -> Self {
        Self {
            id: Id::default(),
            perms,
            vaddr,
            offset,
            size,
            idmap: IdMap::new(),
            cursor: 0,
        }
    }

    pub(crate) fn offset(&self) -> Option<usize> {
        self.offset
    }

    /// The last virtual address occupied by this section (size - 1)
    pub fn last_addr(&self) -> VAddr {
        self.vaddr + self.size as VAddr - 1
    }

    /// Check whether this section contains the givem virtual address
    pub fn contains_address(&self, vaddr: VAddr) -> bool {
        self.vaddr <= vaddr && vaddr <= self.last_addr()
    }

    /// The size of this section
    pub fn size(&self) -> usize {
        self.size
    }

    /// The permissions of this section
    pub fn perms(&self) -> Perms {
        self.perms
    }

    /// The virtual address of this section
    pub fn vaddr(&self) -> VAddr {
        self.vaddr
    }

    /// Change the size of this section
    pub fn set_size(&mut self, size: usize) {
        self.size = size;
    }
    
    /// Change the permissions of this section
    pub fn set_perms(&mut self, perms: Perms) {
        self.perms = perms;
    }

    /// Change the virtual address of this section
    pub fn set_vaddr(&mut self, vaddr: VAddr) {
        self.vaddr = vaddr;
    }

    /// Create a [`SectionBuilder`] that can build Sections from scratch
    pub fn builder() -> SectionBuilder {
        SectionBuilder {
            perms: None,
            vaddr: None,
            size: None,
        }
    }
}

idmap_functions!(Section, Symbol, symbol);

impl HasId for Section {
    fn id(&self) -> Id {
        self.id
    }
}

impl HasIdMut for Section {
    fn id_mut(&mut self) -> &mut Id {
        &mut self.id
    }
}

/// The SectionBuilder can be used to build a [`Section`] from scratch
pub struct SectionBuilder {
    perms: Option<Perms>,
    vaddr: Option<VAddr>,
    size: Option<usize>,
}

impl SectionBuilder {
    /// Set the permissions of this section
    pub fn perms(mut self, perms: Perms) -> Self {
        self.perms = Some(perms);
        self
    }

    /// Set the virtual address of this section
    pub fn vaddr(mut self, vaddr: VAddr) -> Self {
        self.vaddr = Some(vaddr);
        self
    }

    /// Set the size of this section
    pub fn size(mut self, size: usize) -> Self {
        self.size = Some(size);
        self
    }

    /// Finally, create the [`Section`]
    pub fn build(self) -> Result<Section, &'static str> {
        let perms = self.perms.ok_or("Section permissions were not set")?;
        let vaddr = self.vaddr.ok_or("Section address was not set")?;
        let size = self.size.ok_or("Section size was not set")?;
        Ok(Section::new(perms, vaddr, None, size))
    }
}

pub(crate) struct SectionParser {
    sections: Vec<Section>,
}

impl SectionParser {
    pub(crate) fn parse(elf: &goblin::elf::Elf, content: &[u8], listing: &ListingManager, event_pool: &mut EventPool) -> Result<IdMap<Section>, LoaderError> {
        /* Parse sections */
        let mut parser = Self::new();
        parser.parse_program_headers(elf)?;
        parser.parse_section_headers(elf)?;
        parser.merge_sections();
        parser.verify(elf)?;

        /*
        #[cfg(test)]
        {
            parser.dump_sections();
        }
        */

        /* Parse symbols */
        for section in &mut parser.sections {
            section.idmap = SymbolParser::parse(elf, section, content, listing, event_pool)?;
        }

        /* Build IdMap */
        let mut map = IdMap::new();

        for section in parser.sections {
            map.insert(section);
        }

        Ok(map)
    }

    fn new() -> Self {
        Self {
            sections: Vec::new(),
        }
    }

    fn parse_program_headers(&mut self, elf: &goblin::elf::Elf) -> Result<(), LoaderError> {
        for ph in &elf.program_headers {
            if ph.p_type == goblin::elf::program_header::PT_LOAD {
                /* Parse permissions.
                  The compiler might merge r-x and r-- sections into the
                  same r-x segment so we ignore the x bit in the segment flags
                  since we don't want to lift data into the IR.
                  The only time a squid::Section can become executable is when the
                  underlying ELF section is executable.
                */
                let mut perms = Perms::from_segment_flags(ph.p_flags);

                if perms.is_inaccessible() {
                    continue;
                }

                if perms.is_readable() || perms.is_writable() {
                    perms.clear_executable();
                }

                if ph.p_memsz < ph.p_filesz {
                    return Err(LoaderError::InvalidELF("Segment memsz < filesz".to_string()));
                }

                /* Parse memory layout. Split segment on p_filesz. */
                let uninit_size = ph.p_memsz - ph.p_filesz;

                if ph.p_filesz > 0 {
                    self.add_section(perms, ph.p_vaddr as VAddr, Some(ph.p_offset as usize), ph.p_filesz as usize, true)?;
                }

                if uninit_size > 0 {
                    self.add_section(perms, (ph.p_vaddr + ph.p_filesz) as VAddr, None, uninit_size as usize, true)?;
                }
            }
        }

        Ok(())
    }

    fn parse_section_headers(&mut self, elf: &goblin::elf::Elf) -> Result<(), LoaderError> {
        for sh in &elf.section_headers {
            if sh.is_alloc() && (sh.sh_flags & goblin::elf::section_header::SHF_TLS as u64) == 0 {
                let offset = match sh.sh_type {
                    goblin::elf::section_header::SHT_NOBITS => None,
                    _ => Some(sh.sh_offset as usize),
                };

                self.add_section(Perms::from_section_header(sh), sh.sh_addr as VAddr, offset, sh.sh_size as usize, false)?;
            }
        }

        Ok(())
    }

    fn add_section(&mut self, perms: Perms, vaddr: VAddr, offset: Option<usize>, size: usize, from_segment: bool) -> Result<(), LoaderError> {
        if size == 0 {
            return Ok(());
        } else if perms.is_writable() && perms.is_executable() {
            return Err(LoaderError::InvalidELF("Binary contains rwx sections/segments".to_string()));
        }

        let new_section = Section::new(perms, vaddr, offset, size);

        match self.locate_section(&new_section) {
            Ok(idx) => {
                if from_segment {
                    return Err(LoaderError::InvalidELF("Found overlapping segments".to_string()));
                }

                /* If we have a duplicate just update the permissions and offset */
                let old_section = &mut self.sections[idx];
                if new_section.vaddr == old_section.vaddr && new_section.last_addr() == old_section.last_addr() {
                    old_section.perms = new_section.perms;
                    old_section.offset = new_section.offset;
                    return Ok(());
                }

                /* Otherwise we have to split the old section into two or three parts */
                let mut old_section = self.sections.remove(idx);

                if new_section.vaddr() == old_section.vaddr() {
                    old_section.vaddr += new_section.size() as VAddr;
                    if let Some(offset) = &mut old_section.offset {
                        *offset += new_section.size();
                    }
                    old_section.size -= new_section.size();

                    self.sections.insert(idx, new_section);
                    self.sections.insert(idx + 1, old_section);
                } else if new_section.last_addr() == old_section.last_addr() {
                    old_section.size -= new_section.size();

                    self.sections.insert(idx, old_section);
                    self.sections.insert(idx + 1, new_section);
                } else {
                    let mut left = Section::new(old_section.perms, old_section.vaddr, old_section.offset, old_section.size);
                    let mut right = old_section;

                    left.size = (new_section.vaddr - left.vaddr) as usize;

                    let shift_amount = left.size() + new_section.size();
                    right.vaddr += shift_amount as VAddr;
                    if let Some(offset) = &mut right.offset {
                        *offset += shift_amount;
                    }
                    right.size -= shift_amount;

                    self.sections.insert(idx, left);
                    self.sections.insert(idx + 1, new_section);
                    self.sections.insert(idx + 2, right);
                }
            },
            Err(idx) => {
                if !from_segment {
                    return Err(LoaderError::InvalidELF(format!("Section not in any segment: {:#x}", vaddr)));
                }

                self.sections.insert(idx, new_section);
            },
        }

        Ok(())
    }

    fn locate_section(&self, section: &Section) -> Result<usize, usize> {
        self.sections.binary_search_by(|x| {
            if x.contains_address(section.vaddr) && x.contains_address(section.last_addr()) {
                Ordering::Equal
            } else {
                let l = x.vaddr.cmp(&section.vaddr);
                let r = x.vaddr.cmp(&section.last_addr());
                assert_eq!(l, r, "Overlapping sections: x={:?} section={:?}", x, section);
                l
            }
        })
    }

    fn merge_sections(&mut self) {
        let mut i = 1;

        while i < self.sections.len() {
            let l = &self.sections[i - 1];
            let r = &self.sections[i];

            let same_perms = l.perms() == r.perms();
            let cont_vaddr = l.vaddr() + l.size() as VAddr == r.vaddr();
            let cont_offset = l.offset().map(|x| x + l.size()) == r.offset();

            if same_perms && cont_vaddr && cont_offset {
                let section = self.sections.remove(i);
                self.sections[i - 1].size += section.size();
            } else {
                i += 1;
            }
        }
    }

    fn verify(&self, elf: &goblin::elf::Elf) -> Result<(), LoaderError> {
        /* Check for continuous memory layout */
        for ph in &elf.program_headers {
            if ph.p_type == goblin::elf::program_header::PT_LOAD {
                /* Find starting index */
                let mut idx = 0;

                while idx < self.sections.len() && self.sections[idx].vaddr < ph.p_vaddr {
                    idx += 1;
                }

                assert!(idx < self.sections.len());

                /* Check for continuity */
                let end_addr = ph.p_vaddr + ph.p_filesz;
                let mut vaddr_cursor = ph.p_vaddr as VAddr;

                while idx < self.sections.len() && self.sections[idx].vaddr < end_addr {
                    assert_eq!(self.sections[idx].vaddr(), vaddr_cursor);
                    vaddr_cursor += self.sections[idx].size() as VAddr;
                    idx += 1;
                }

                assert_eq!(vaddr_cursor, end_addr);
            }
        }

        /* Verify each section */
        for section in &self.sections {
            assert!(!section.perms().is_inaccessible());
            assert!(section.size() > 0);
        }

        Ok(())
    }

    /*
    #[cfg(test)]
    pub fn dump_sections(&self) {
        for section in &self.sections {
            print!("{:08x}  ", section.vaddr());

            if let Some(offset) = section.offset() {
                print!("{:06x}", offset);
            } else {
                print!("      ");
            }

            print!("  {:04x}  ", section.size());

            let perms = section.perms();
            let r = if perms.is_readable() { "r" } else { "-" };
            let w = if perms.is_writable() { "w" } else { "-" };
            let x = if perms.is_executable() { "x" } else { "-" };
            println!("{}{}{}", r, w, x);
        }
    }
    */
}
