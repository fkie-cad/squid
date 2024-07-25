use crate::frontend::error::LoaderError;

#[derive(Debug, PartialEq, Eq, Hash)]
pub(crate) enum Relocation {
    Offset(usize),
    SymbolImport(String),
    TlsSymbolImport(String),
}

fn reloc_size(typ: u32) -> usize {
    match typ {
        goblin::elf::reloc::R_RISCV_RELATIVE
        | goblin::elf::reloc::R_RISCV_TLS_TPREL64
        | goblin::elf::reloc::R_RISCV_JUMP_SLOT
        | goblin::elf::reloc::R_RISCV_64 => 8,
        _ => todo!("{}", typ),
    }
}

pub(crate) fn parse_relocations(
    elf: &goblin::elf::Elf,
    parent_start: u64,
    parent_size: u64,
) -> Result<Vec<(Relocation, u64, usize)>, LoaderError> {
    if !elf.dynrels.is_empty() {
        return Err(LoaderError::InvalidELF("Binary uses rels instead of relas".to_string()));
    }

    let mut result = Vec::new();

    for rela in elf.dynrelas.iter() {
        let vaddr = rela.r_offset;
        let size = reloc_size(rela.r_type);

        let has_start = parent_start <= vaddr && vaddr < parent_start + parent_size;
        let has_end =
            parent_start <= (vaddr + size as u64 - 1) && (vaddr + size as u64 - 1) < parent_start + parent_size;

        if has_start != has_end {
            return Err(LoaderError::InvalidELF(format!(
                "Relocation at {:#x} overlaps parent {:#x}",
                vaddr, parent_start
            )));
        }

        if has_start {
            let addend = rela.r_addend.unwrap();

            let rel = if rela.r_sym == 0 {
                // Use zero as symbol value

                match rela.r_type {
                    goblin::elf::reloc::R_RISCV_RELATIVE => Relocation::Offset(addend as usize),
                    t => todo!("{}", t),
                }
            } else {
                let linked_sym = elf.dynsyms.get(rela.r_sym).unwrap();

                // Is this even correct? Nobody documents shit anymore
                if linked_sym.is_import() {
                    assert_eq!(addend, 0);

                    let name = elf.dynstrtab.get_at(linked_sym.st_name).unwrap().to_string();

                    match rela.r_type {
                        goblin::elf::reloc::R_RISCV_JUMP_SLOT => Relocation::SymbolImport(name),
                        goblin::elf::reloc::R_RISCV_64 => Relocation::SymbolImport(name),
                        goblin::elf::reloc::R_RISCV_TLS_TPREL64 => Relocation::TlsSymbolImport(name),
                        t => todo!("{}", t),
                    }
                } else {
                    match rela.r_type {
                        goblin::elf::reloc::R_RISCV_64 => {
                            Relocation::Offset(linked_sym.st_value as usize + addend as usize)
                        },
                        goblin::elf::reloc::R_RISCV_JUMP_SLOT => Relocation::Offset(linked_sym.st_value as usize),
                        t => todo!("{}", t),
                    }
                }
            };

            result.push((rel, vaddr, size));
        }
    }

    Ok(result)
}
