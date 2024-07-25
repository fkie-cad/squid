use std::collections::HashMap;
use crate::backends::clang::{AddressSpace, address::POINTER_CODE_SHIFT};
use crate::frontend::{
    ProcessImage,
    VAddr,
};

/// The type of a symbol in the runtime's symbol store
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub enum SymbolType {
    Function,
    Data,
}

/// The visibility of a symbol in the runtime's symbol store
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub enum SymbolVisibility {
    Public,
    Private,
}

/// The Symbols in the ClangRuntime are constructed from the symbols in the
/// process image except that there is one runtime Symbol for every private +
/// public name of a process image symbol.
#[derive(Debug, Clone)]
pub struct Symbol {
    name: String,
    visibility: SymbolVisibility,
    address: VAddr,
    size: usize,
    typ: SymbolType,
}

impl Symbol {
    /// Return true if this symbol is a function
    pub fn is_function(&self) -> bool {
        matches!(self.typ, SymbolType::Function)
    }

    /// Return true if this symbol holds data
    pub fn is_data(&self) -> bool {
        matches!(self.typ, SymbolType::Data)
    }

    /// Get the virtual address of this symbol
    pub fn address(&self) -> VAddr {
        self.address
    }

    /// Get the size of this symbol
    pub fn size(&self) -> usize {
        self.size
    }

    /// Return true if this is a publicly exported symbol (from the .dynsym)
    pub fn is_public(&self) -> bool {
        matches!(self.visibility, SymbolVisibility::Public)
    }

    /// Return true if this is a private symbol (from .symtab)
    pub fn is_private(&self) -> bool {
        matches!(self.visibility, SymbolVisibility::Private)
    }

    /// Get the name of this symbol
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Check whether this symbol contains the given address
    pub fn contains_address(&self, addr: VAddr) -> bool {
        match AddressSpace::decode(addr) {
            AddressSpace::Data(_) => self.address <= addr && addr < self.address + self.size as VAddr,
            AddressSpace::Code(_) => {
                let search_addr = addr >> POINTER_CODE_SHIFT;
                let this_addr = self.address >> POINTER_CODE_SHIFT;
                this_addr <= search_addr && search_addr < this_addr + self.size as VAddr
            },
        }
    }
}

pub(crate) fn create_symbol_store(image: &ProcessImage) -> HashMap<String, Vec<Symbol>> {
    let mut ret = HashMap::new();

    for elf in image.iter_elfs() {
        let file: &str = &elf.path().file_name().unwrap().to_string_lossy();

        for section in elf.iter_sections() {
            for symbol in section.iter_symbols() {
                let end_addr = symbol.last_addr() + 1;

                for public_name in symbol.public_names() {
                    let address = symbol.public_name(public_name).unwrap();
                    let size = (end_addr - address) as usize;
                    let typ = if section.perms().is_executable() { SymbolType::Function } else { SymbolType::Data };

                    ret.entry(file.to_string()).or_insert_with(Vec::new).push(Symbol {
                        name: public_name.clone(),
                        visibility: SymbolVisibility::Public,
                        address,
                        size,
                        typ,
                    });
                }

                for private_name in symbol.private_names() {
                    let address = symbol.private_name(private_name).unwrap();
                    let size = (end_addr - address) as usize;
                    let typ = if section.perms().is_executable() { SymbolType::Function } else { SymbolType::Data };

                    ret.entry(file.to_string()).or_insert_with(Vec::new).push(Symbol {
                        name: private_name.clone(),
                        visibility: SymbolVisibility::Private,
                        address,
                        size,
                        typ,
                    });
                }
            }
        }
    }

    ret
}
