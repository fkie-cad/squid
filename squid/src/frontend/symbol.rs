use std::{
    cmp::Ordering,
    collections::{
        btree_map::Keys,
        BTreeMap,
        HashSet,
    },
};

use goblin;
use paste::paste;

use crate::{
    event::EventPool,
    frontend::{
        chunk::{
            Chunk,
            ChunkParser,
        },
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
        section::Section,
    },
    listing::ListingManager,
};

#[derive(Debug, Hash)]
pub struct Symbol {
    id: Id,
    public_names: BTreeMap<String, VAddr>,
    private_names: BTreeMap<String, VAddr>,
    vaddr: VAddr,
    size: usize,
    file: Option<String>,
    idmap: IdMap<Chunk>,
    cursor: usize,
}

impl Symbol {
    fn new(public_names: BTreeMap<String, VAddr>, private_names: BTreeMap<String, VAddr>, vaddr: VAddr, size: usize) -> Self {
        Self {
            id: Id::default(),
            public_names,
            private_names,
            vaddr,
            size,
            idmap: IdMap::new(),
            file: None,
            cursor: 0,
        }
    }

    fn new_public(name: String, vaddr: VAddr, size: usize) -> Self {
        Self {
            id: Id::default(),
            public_names: {
                let mut map = BTreeMap::new();
                map.insert(name, 0);
                map
            },
            private_names: BTreeMap::new(),
            vaddr,
            size,
            idmap: IdMap::new(),
            file: None,
            cursor: 0,
        }
    }

    fn new_private(name: String, vaddr: VAddr, size: usize) -> Self {
        Self {
            id: Id::default(),
            public_names: BTreeMap::new(),
            private_names: {
                let mut map = BTreeMap::new();
                map.insert(name, 0);
                map
            },
            vaddr,
            size,
            idmap: IdMap::new(),
            file: None,
            cursor: 0,
        }
    }

    pub fn vaddr(&self) -> VAddr {
        self.vaddr
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn last_addr(&self) -> VAddr {
        self.vaddr + self.size as VAddr - 1
    }

    pub fn contains_address(&self, vaddr: VAddr) -> bool {
        self.vaddr <= vaddr && vaddr <= self.last_addr()
    }

    pub fn name<S: AsRef<str>>(&self, name: S) -> Option<VAddr> {
        if let Some(vaddr) = self.public_name(&name) {
            return Some(vaddr);
        }

        if let Some(vaddr) = self.private_name(name) {
            return Some(vaddr);
        }

        None
    }

    pub fn public_name<S: AsRef<str>>(&self, name: S) -> Option<VAddr> {
        self.public_names.get(name.as_ref()).map(|offset| self.vaddr + *offset)
    }

    pub fn private_name<S: AsRef<str>>(&self, name: S) -> Option<VAddr> {
        self.private_names.get(name.as_ref()).map(|offset| self.vaddr + *offset)
    }

    pub fn public_names(&self) -> Keys<String, VAddr> {
        self.public_names.keys()
    }

    pub fn private_names(&self) -> Keys<String, VAddr> {
        self.private_names.keys()
    }

    pub fn file(&self) -> Option<&str> {
        self.file.as_deref()
    }

    pub fn set_size(&mut self, size: usize) {
        self.size = size;
    }

    pub fn set_vaddr(&mut self, vaddr: VAddr) {
        self.vaddr = vaddr;
    }
    
    pub fn set_public_name<S: Into<String>>(&mut self, name: S, value: VAddr) {
        self.public_names.insert(name.into(), value - self.vaddr);
    }
    
    pub fn set_private_name<S: Into<String>>(&mut self, name: S, value: VAddr) {
        self.private_names.insert(name.into(), value - self.vaddr);
    }

    pub fn builder() -> SymbolBuilder {
        SymbolBuilder {
            public_names: HashSet::new(),
            private_names: HashSet::new(),
            vaddr: None,
            size: None,
        }
    }
}

idmap_functions!(Symbol, Chunk, chunk);

impl HasId for Symbol {
    fn id(&self) -> Id {
        self.id
    }
}

impl HasIdMut for Symbol {
    fn id_mut(&mut self) -> &mut Id {
        &mut self.id
    }
}

pub struct SymbolBuilder {
    public_names: HashSet<String>,
    private_names: HashSet<String>,
    vaddr: Option<VAddr>,
    size: Option<usize>,
}

impl SymbolBuilder {
    pub fn public_name<S: Into<String>>(mut self, name: S) -> Self {
        self.public_names.insert(name.into());
        self
    }

    pub fn private_name<S: Into<String>>(mut self, name: S) -> Self {
        self.private_names.insert(name.into());
        self
    }

    pub fn vaddr(mut self, vaddr: VAddr) -> Self {
        self.vaddr = Some(vaddr);
        self
    }

    pub fn size(mut self, size: usize) -> Self {
        self.size = Some(size);
        self
    }

    pub fn build(self) -> Result<Symbol, &'static str> {
        let vaddr = self.vaddr.ok_or("Symbol address was not set")?;
        let size = self.size.ok_or("Symbol size was not set")?;
        let mut public_names = BTreeMap::new();
        let mut private_names = BTreeMap::new();

        for name in self.public_names {
            public_names.insert(name, 0);
        }
        for name in self.private_names {
            private_names.insert(name, 0);
        }

        Ok(Symbol {
            id: Id::default(),
            public_names,
            private_names,
            vaddr,
            size,
            file: None,
            idmap: IdMap::new(),
            cursor: 0,
        })
    }
}

const MAPPING_SYMBOLS: &[&str] = &["$x", "$d"];

fn ignore_symbol_type(typ: u8) -> bool {
    match typ {
        goblin::elf::sym::STT_FILE
        | goblin::elf::sym::STT_HIOS
        | goblin::elf::sym::STT_HIPROC
        | goblin::elf::sym::STT_LOOS
        | goblin::elf::sym::STT_LOPROC
        | goblin::elf::sym::STT_SECTION
        | goblin::elf::sym::STT_TLS => true,
        goblin::elf::sym::STT_NUM => todo!("what's STT_NUM?"),
        _ => false,
    }
}

#[derive(Debug)]
pub(crate) struct SymbolParser {
    symbols: Vec<Symbol>,
}

impl SymbolParser {
    pub(crate) fn parse(elf: &goblin::elf::Elf, parent: &Section, content: &[u8], listing: &ListingManager, event_pool: &mut EventPool) -> Result<IdMap<Symbol>, LoaderError> {
        /* Parse symbol tables */
        let mut parser = Self::new();
        parser.find_candidate_symbols(elf, parent)?;

        loop {
            if parser.handle_overlaps(parent)? {
                break;
            }
        }

        parser.check_sorted(parent);
        parser.fill_gaps(parent);

        for (addr, names) in parser.find_global_split_targets(elf, parent) {
            parser.split_symbol(addr, names, Vec::new());
        }

        for (addr, names) in parser.find_local_split_targets(elf, parent) {
            parser.split_symbol(addr, Vec::new(), names);
        }

        if parent.perms().is_executable() {
            parser.parse_files(elf, parent);
        }

        parser.handle_plt();
        parser.handle_got();
        parser.remove_mapping_symbols();
        parser.verify(parent);

        /* Parse chunks */
        for symbol in &mut parser.symbols {
            symbol.idmap = ChunkParser::parse(elf, symbol, parent, content, listing, event_pool)?;
        }

        /* Build IdMap */
        let mut map = IdMap::new();

        for symbol in parser.symbols {
            map.insert(symbol);
        }

        Ok(map)
    }

    fn new() -> Self {
        Self {
            symbols: Vec::new(),
        }
    }

    fn verify(&self, parent: &Section) {
        let mut cursor = parent.vaddr();

        for symbol in &self.symbols {
            assert_eq!(symbol.vaddr, cursor);
            cursor += symbol.size as VAddr;

            for offset in symbol.public_names.values().chain(symbol.private_names.values()) {
                assert!(*offset < symbol.size as VAddr);
            }

            if parent.perms().is_executable() {
                assert!(symbol.private_name(".plt").is_some() || symbol.file().is_some());
            }
        }

        assert_eq!(cursor, parent.last_addr() + 1);
    }

    fn remove_mapping_symbols(&mut self) {
        for symbol in &mut self.symbols {
            for mapping_symbol in MAPPING_SYMBOLS {
                symbol.private_names.remove(*mapping_symbol);
            }
        }
    }

    fn merge_symbols(&mut self, idx: usize) {
        let rem = self.symbols.remove(idx + 1);
        let prev = &mut self.symbols[idx];
        let prev_size = prev.size as VAddr;

        prev.size += rem.size;

        for (name, offset) in rem.private_names {
            assert!(prev.private_names.insert(name, prev_size + offset).is_none());
        }

        for (name, offset) in rem.public_names {
            assert!(prev.public_names.insert(name, prev_size + offset).is_none());
        }
    }

    fn handle_plt(&mut self) {
        for i in 1..self.symbols.len() {
            let sym = &self.symbols[i];

            if sym.public_names.is_empty() && sym.private_names.len() == 1 && sym.private_name("_PROCEDURE_LINKAGE_TABLE_").is_some() {
                self.merge_symbols(i - 1);
                break;
            }
        }
    }

    fn handle_got(&mut self) {
        for i in 1..self.symbols.len() {
            let curr_has_symbol = self.symbols[i].private_name("_GLOBAL_OFFSET_TABLE_").is_some();
            let prev_is_got = self.symbols[i - 1].private_name(".got").is_some();

            if prev_is_got && curr_has_symbol {
                self.merge_symbols(i - 1);
                break;
            }
        }
    }

    fn parse_files(&mut self, elf: &goblin::elf::Elf, parent: &Section) {
        let mut current_file = None;
        let mut mappings = Vec::new();

        /* Find out file mappings by parsing FILE and $x symbols */
        for symbol in elf.syms.iter() {
            let vaddr = symbol.st_value as VAddr;

            if symbol.st_type() == goblin::elf::sym::STT_FILE {
                let filename = elf.strtab.get_at(symbol.st_name).unwrap();

                if filename.is_empty() {
                    break;
                } else {
                    current_file = Some(filename);
                }
            } else if symbol.st_type() == goblin::elf::sym::STT_NOTYPE && parent.contains_address(vaddr) {
                let name = elf.strtab.get_at(symbol.st_name).unwrap();

                if name != "$x" {
                    continue;
                } else if let Some(current_file) = &current_file {
                    mappings.push((vaddr, *current_file));
                }
            }
        }

        /* Bring mappings into order */
        mappings.sort_by(|a, b| a.0.cmp(&b.0));

        /* Set the symbol filenames */
        if !mappings.is_empty() {
            mappings.push((parent.last_addr() + 1, "<INVALID>"));

            for i in 0..mappings.len() - 1 {
                let mapping_start = mappings[i].0;
                let mapping_end = mappings[i + 1].0;

                if mapping_end == mapping_start {
                    continue;
                }

                for symbol in &mut self.symbols {
                    let has_start = mapping_start <= symbol.vaddr && symbol.vaddr < mapping_end;
                    let has_end = mapping_start <= symbol.last_addr() && symbol.last_addr() < mapping_end;

                    match (has_start, has_end) {
                        (true, true) => symbol.file = Some(mappings[i].1.to_string()),
                        (false, false) => {},
                        _ => panic!("Symbol overlaps file mapping: {:?}", symbol),
                    }
                }
            }
        }
    }

    fn split_symbol(&mut self, vaddr: VAddr, globals: Vec<String>, locals: Vec<String>) {
        let result = self.symbols.binary_search_by(|x| if x.contains_address(vaddr) { Ordering::Equal } else { x.vaddr.cmp(&vaddr) });

        match result {
            Ok(idx) => {
                let symbol = &mut self.symbols[idx];

                if vaddr == symbol.vaddr {
                    for global in globals {
                        if let Some(old_offset) = symbol.public_names.insert(global, 0) {
                            assert_eq!(old_offset, 0);
                        }
                    }

                    for local in locals {
                        if let Some(old_offset) = symbol.private_names.insert(local, 0) {
                            assert_eq!(old_offset, 0);
                        }
                    }
                } else {
                    let end = symbol.last_addr() + 1;
                    let new_size = vaddr - symbol.vaddr;
                    symbol.size = new_size as usize;

                    let mut global_names = BTreeMap::new();
                    let mut local_names = BTreeMap::new();

                    for (name, offset) in symbol.public_names.extract_if(|_, v| *v >= new_size) {
                        global_names.insert(name, offset - new_size);
                    }

                    for (name, offset) in symbol.private_names.extract_if(|_, v| *v >= new_size) {
                        local_names.insert(name, offset - new_size);
                    }

                    for global in globals {
                        global_names.insert(global, 0);
                    }

                    for local in locals {
                        local_names.insert(local, 0);
                    }

                    self.symbols.insert(idx + 1, Symbol::new(global_names, local_names, vaddr, (end - vaddr) as usize));
                }
            },
            Err(_) => unreachable!(),
        }
    }

    fn find_local_split_targets(&self, elf: &goblin::elf::Elf, parent: &Section) -> BTreeMap<VAddr, Vec<String>> {
        let mut targets = BTreeMap::new();

        /* Split on local symbols with size = 0 or section symbols */
        for symbol in elf.syms.iter() {
            let name = if symbol.st_type() == goblin::elf::sym::STT_SECTION && symbol.st_value > 0 {
                elf.shdr_strtab.get_at(elf.section_headers[symbol.st_shndx].sh_name).unwrap()
            } else if !ignore_symbol_type(symbol.st_type()) && symbol.st_size == 0 && symbol.st_value > 0 {
                elf.strtab.get_at(symbol.st_name).unwrap()
            } else {
                continue;
            };
            let addr = symbol.st_value as VAddr;

            if parent.contains_address(addr) {
                targets.entry(addr).or_insert(Vec::new()).push(name.to_string());
            }
        }

        targets
    }

    fn find_global_split_targets(&self, elf: &goblin::elf::Elf, parent: &Section) -> BTreeMap<VAddr, Vec<String>> {
        let mut targets = BTreeMap::new();

        /* Split on exported symbols with size = 0 */
        for symbol in elf.dynsyms.iter() {
            if ignore_symbol_type(symbol.st_type()) || symbol.st_size > 0 || symbol.st_value == 0 {
                continue;
            }

            let addr = symbol.st_value as VAddr;
            let name = elf.dynstrtab.get_at(symbol.st_name).unwrap();

            if parent.contains_address(addr) {
                targets.entry(addr).or_insert(Vec::new()).push(name.to_string());
            }
        }

        targets
    }

    fn fill_gaps(&mut self, parent: &Section) {
        let mut cursor = parent.vaddr();
        let mut i = 0;

        while i < self.symbols.len() {
            let sym = &self.symbols[i];

            if cursor < sym.vaddr {
                self.symbols.insert(i, Symbol::new(BTreeMap::new(), BTreeMap::new(), cursor, (sym.vaddr - cursor) as usize));
            }

            cursor += self.symbols[i].size as VAddr;
            i += 1;
        }

        let section_end = parent.last_addr() + 1;

        if cursor < section_end {
            self.symbols.push(Symbol::new(BTreeMap::new(), BTreeMap::new(), cursor, (section_end - cursor) as usize));
        }
    }

    fn check_sorted(&self, parent: &Section) {
        let mut cursor = parent.vaddr();

        for symbol in &self.symbols {
            assert!(symbol.vaddr >= cursor);
            cursor = symbol.vaddr + symbol.size as VAddr;
        }
    }

    fn handle_overlaps(&mut self, parent: &Section) -> Result<bool, LoaderError> {
        let mut overlaps = Vec::new();
        let mut cursor = parent.vaddr();
        let mut i = 0;

        /* Find overlapping symbols */
        while i < self.symbols.len() {
            let sym = &self.symbols[i];

            if sym.vaddr < cursor {
                if parent.perms().is_executable() {
                    return Err(LoaderError::InvalidELF(format!("Executable section {:#x} has overlapping symbols", parent.vaddr())));
                } else {
                    overlaps.push(self.symbols.remove(i));
                }
            } else {
                cursor = sym.vaddr + sym.size as VAddr;
                i += 1;
            }
        }

        let done = overlaps.is_empty();

        /* Merge overlapping symbols */
        for overlap in overlaps {
            let mut min_vaddr = overlap.vaddr;
            let mut max_vaddr = overlap.last_addr();
            let mut contact = vec![overlap];

            let mut i = 0;
            while i < self.symbols.len() {
                let sym = &self.symbols[i];

                if sym.contains_address(min_vaddr) || sym.contains_address(max_vaddr) {
                    contact.push(self.symbols.remove(i));
                } else {
                    i += 1;
                }
            }

            assert!(contact.len() > 1);

            for symbol in &contact {
                min_vaddr = std::cmp::min(min_vaddr, symbol.vaddr);
                max_vaddr = std::cmp::max(max_vaddr, symbol.last_addr());
            }

            let mut global_names = BTreeMap::new();
            let mut local_names = BTreeMap::new();

            for symbol in contact {
                for (name, offset) in symbol.public_names {
                    let fixed_addr = symbol.vaddr + offset;
                    let new_offset = fixed_addr - min_vaddr;
                    assert!(global_names.insert(name, new_offset).is_none());
                }

                for (name, offset) in symbol.private_names {
                    let fixed_addr = symbol.vaddr + offset;
                    let new_offset = fixed_addr - min_vaddr;
                    assert!(local_names.insert(name, new_offset).is_none());
                }
            }

            let new_symbol = Symbol::new(global_names, local_names, min_vaddr, (max_vaddr + 1 - min_vaddr) as usize);

            match self.locate_symbol(new_symbol.vaddr, new_symbol.size) {
                Ok(_) => unreachable!(),
                Err(idx) => self.symbols.insert(idx, new_symbol),
            }
        }

        Ok(done)
    }

    fn find_candidate_symbols(&mut self, elf: &goblin::elf::Elf, parent: &Section) -> Result<(), LoaderError> {
        /* Parse global symbols */
        for symbol in elf.dynsyms.iter() {
            if ignore_symbol_type(symbol.st_type()) || symbol.st_size == 0 || symbol.st_value == 0 {
                continue;
            }

            let start = symbol.st_value as VAddr;
            let last_addr = start + symbol.st_size - 1;
            let name = elf.dynstrtab.get_at(symbol.st_name).unwrap();

            match (parent.contains_address(start), parent.contains_address(last_addr)) {
                (true, true) => {},
                (false, false) => continue,
                _ => {
                    return Err(LoaderError::InvalidELF(format!("Symbol {:#x} partially out-of-bounds in section {:#x}", start, parent.vaddr())));
                },
            }

            match self.locate_symbol(symbol.st_value as VAddr, symbol.st_size as usize) {
                Ok(idx) => {
                    self.symbols[idx].public_names.insert(name.to_string(), 0);
                },
                Err(idx) => {
                    self.symbols.insert(idx, Symbol::new_public(name.to_string(), start, symbol.st_size as usize));
                },
            }
        }

        /* Parse local symbols  */
        for symbol in elf.syms.iter() {
            if ignore_symbol_type(symbol.st_type()) || symbol.st_size == 0 || symbol.st_value == 0 {
                continue;
            }

            let start = symbol.st_value as VAddr;
            let last_addr = start + symbol.st_size - 1;
            let name = elf.strtab.get_at(symbol.st_name).unwrap();

            match (parent.contains_address(start), parent.contains_address(last_addr)) {
                (true, true) => {},
                (false, false) => continue,
                _ => {
                    return Err(LoaderError::InvalidELF(format!("Symbol {:#x} partially out-of-bounds in section {:#x}", start, parent.vaddr())));
                },
            }

            match self.locate_symbol(symbol.st_value as VAddr, symbol.st_size as usize) {
                Ok(idx) => {
                    self.symbols[idx].private_names.insert(name.to_string(), 0);
                },
                Err(idx) => {
                    self.symbols.insert(idx, Symbol::new_private(name.to_string(), start, symbol.st_size as usize));
                },
            }
        }

        Ok(())
    }

    fn locate_symbol(&self, vaddr: VAddr, size: usize) -> Result<usize, usize> {
        self.symbols.binary_search_by(|x| (x.vaddr, -(x.size as i64)).cmp(&(vaddr, -(size as i64))))
    }
}

#[cfg(test)]
#[test]
fn test_overlap() {
    use crate::frontend::perms::Perms;

    let section = Section::new(Perms::default(), 0, None, 4096);

    /* TEST1: Overlap at beginning */
    let mut parser = SymbolParser {
        symbols: vec![Symbol::new_public("A".to_string(), 1000, 64), Symbol::new_public("B".to_string(), 1000, 32)],
    };

    loop {
        if parser.handle_overlaps(&section).unwrap() {
            break;
        }
    }

    println!("TEST1: {:#?}", parser);
    assert_eq!(parser.symbols.len(), 1);
    assert_eq!(parser.symbols[0].vaddr, 1000);
    assert_eq!(parser.symbols[0].size, 64);
    assert_eq!(parser.symbols[0].public_names.len(), 2);

    /* TEST2: Overlap at end */
    let mut parser = SymbolParser {
        symbols: vec![Symbol::new_public("A".to_string(), 1000, 64), Symbol::new_public("B".to_string(), 1032, 32)],
    };

    loop {
        if parser.handle_overlaps(&section).unwrap() {
            break;
        }
    }

    println!("TEST2: {:#?}", parser);
    assert_eq!(parser.symbols.len(), 1);
    assert_eq!(parser.symbols[0].vaddr, 1000);
    assert_eq!(parser.symbols[0].size, 64);
    assert_eq!(parser.symbols[0].public_names.len(), 2);

    /* TEST3: Triple overlap */
    let mut parser = SymbolParser {
        symbols: vec![Symbol::new_public("A".to_string(), 1000, 64), Symbol::new_public("B".to_string(), 1032, 64), Symbol::new_public("C".to_string(), 1064, 32)],
    };

    loop {
        if parser.handle_overlaps(&section).unwrap() {
            break;
        }
    }

    println!("TEST3: {:#?}", parser);
    assert_eq!(parser.symbols.len(), 1);
    assert_eq!(parser.symbols[0].vaddr, 1000);
    assert_eq!(parser.symbols[0].size, 64 + 32);
    assert_eq!(parser.symbols[0].public_names.len(), 3);

    /* TEST4: Double overlap */
    let mut parser = SymbolParser {
        symbols: vec![Symbol::new_public("A".to_string(), 1000, 64), Symbol::new_public("B".to_string(), 1032, 64)],
    };

    loop {
        if parser.handle_overlaps(&section).unwrap() {
            break;
        }
    }

    println!("TEST4: {:#?}", parser);
    assert_eq!(parser.symbols.len(), 1);
    assert_eq!(parser.symbols[0].vaddr, 1000);
    assert_eq!(parser.symbols[0].size, 64 + 32);
    assert_eq!(parser.symbols[0].public_names.len(), 2);

    /* TEST5: Deeply nested */
    let mut parser = SymbolParser {
        symbols: vec![
            Symbol::new_public("A".to_string(), 1000, 128),
            Symbol::new_public("D".to_string(), 1008, 16),
            Symbol::new_public("C".to_string(), 1016, 64),
            Symbol::new_public("E".to_string(), 1016, 32),
            Symbol::new_public("F".to_string(), 1032, 32),
            Symbol::new_public("G".to_string(), 1048, 16),
            Symbol::new_public("B".to_string(), 1120, 16),
        ],
    };

    loop {
        if parser.handle_overlaps(&section).unwrap() {
            break;
        }
    }

    println!("TEST5: {:#?}", parser);
    assert_eq!(parser.symbols.len(), 1);
    assert_eq!(parser.symbols[0].vaddr, 1000);
    assert_eq!(parser.symbols[0].size, 136);
    assert_eq!(parser.symbols[0].public_names.len(), 7);
}

#[cfg(test)]
#[test]
fn test_fill_gaps() {
    use crate::frontend::perms::Perms;

    let section = Section::new(Perms::default(), 0, None, 4096);

    /* TEST1: Stripped */
    let mut parser = SymbolParser {
        symbols: vec![],
    };

    parser.fill_gaps(&section);

    println!("TEST1: {:#?}", parser);
    assert_eq!(parser.symbols.len(), 1);
    assert_eq!(parser.symbols[0].vaddr, 0);
    assert_eq!(parser.symbols[0].size, 4096);

    /* TEST2: Front and back */
    let mut parser = SymbolParser {
        symbols: vec![Symbol::new_private("a".to_string(), 128, 1000)],
    };

    parser.fill_gaps(&section);

    println!("TEST2: {:#?}", parser);
    assert_eq!(parser.symbols.len(), 3);
    assert_eq!(parser.symbols[0].vaddr, 0);
    assert_eq!(parser.symbols[0].size, 128);
    assert_eq!(parser.symbols[1].vaddr, 128);
    assert_eq!(parser.symbols[1].size, 1000);
    assert_eq!(parser.symbols[2].vaddr, 1128);
    assert_eq!(parser.symbols[2].size, 4096 - 1128);

    /* TEST3: Mini mid */
    let mut parser = SymbolParser {
        symbols: vec![Symbol::new_private("a".to_string(), 0, 128), Symbol::new_private("b".to_string(), 129, 4096 - 129)],
    };

    parser.fill_gaps(&section);

    println!("TEST3: {:#?}", parser);
    assert_eq!(parser.symbols.len(), 3);
    assert_eq!(parser.symbols[0].vaddr, 0);
    assert_eq!(parser.symbols[0].size, 128);
    assert_eq!(parser.symbols[1].vaddr, 128);
    assert_eq!(parser.symbols[1].size, 1);
    assert_eq!(parser.symbols[2].vaddr, 129);
    assert_eq!(parser.symbols[2].size, 4096 - 129);
}

#[cfg(test)]
#[test]
fn test_split_symbol() {
    /* TEST1: Stripped */
    let mut parser = SymbolParser {
        symbols: vec![Symbol::new_private("a".to_string(), 0, 4096)],
    };

    parser.split_symbol(1000, vec!["S".to_string()], Vec::new());

    println!("TEST1: {:#?}", parser);
    assert_eq!(parser.symbols.len(), 2);
    assert_eq!(parser.symbols[0].vaddr, 0);
    assert_eq!(parser.symbols[0].size, 1000);
    assert_eq!(parser.symbols[1].vaddr, 1000);
    assert_eq!(parser.symbols[1].size, 3096);

    /* TEST2: Duplicate name */
    parser.split_symbol(1000, vec!["S".to_string()], Vec::new());

    println!("TEST2: {:#?}", parser);
    assert_eq!(parser.symbols[1].public_names.len(), 1);

    /* TEST3: Fix-up offsets */
    let mut parser = SymbolParser {
        symbols: vec![Symbol::new_private("a".to_string(), 0, 4096)],
    };
    parser.symbols[0].private_names.insert("a'".to_string(), 64);

    parser.split_symbol(32, vec!["X".to_string()], Vec::new());

    println!("TEST3: {:#?}", parser);
    assert_eq!(parser.symbols.len(), 2);
    assert_eq!(parser.symbols[0].vaddr, 0);
    assert_eq!(parser.symbols[0].size, 32);
    assert_eq!(parser.symbols[1].vaddr, 32);
    assert_eq!(parser.symbols[1].size, 4096 - 32);
    assert_eq!(parser.symbols[0].private_names.len(), 1);
    assert_eq!(parser.symbols[1].private_names.len(), 1);
}
