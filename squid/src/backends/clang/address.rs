use std::collections::HashMap;

use crate::frontend::{
    ChunkContent,
    HasId,
    ProcessImage,
    VAddr,
};

pub(crate) const POINTER_TAG_SHIFT: u32 = 63;
pub(crate) const POINTER_TAG_MASK: VAddr = 0x8000000000000000;
pub(crate) const POINTER_TAG_DATA: VAddr = 0;
pub(crate) const POINTER_TAG_CODE: VAddr = 0x8000000000000000;
pub(crate) const POINTER_CODE_MASK: VAddr = 0x7FFFFFF000000000;
pub(crate) const POINTER_CODE_SHIFT: u32 = 36;

pub(crate) enum AddressSpace {
    Data(usize),
    Code(usize),
}

impl AddressSpace {
    pub(crate) fn decode(addr: VAddr) -> Self {
        match addr & POINTER_TAG_MASK {
            POINTER_TAG_DATA => Self::Data((addr & !POINTER_TAG_MASK) as usize),
            POINTER_TAG_CODE => Self::Code((addr & !POINTER_TAG_MASK) as usize),
            _ => unreachable!(),
        }
    }

    pub(crate) fn encode(&self) -> VAddr {
        match self {
            Self::Data(offset) => {
                let offset = *offset as VAddr;
                assert_eq!(offset & POINTER_TAG_MASK, 0);
                POINTER_TAG_DATA | offset
            },
            Self::Code(index) => {
                let index = *index as VAddr;
                assert_eq!(index & POINTER_TAG_MASK, 0);
                POINTER_TAG_CODE | index
            },
        }
    }
}

#[inline]
fn make_code_address(idx: usize) -> VAddr {
    AddressSpace::Code(idx << POINTER_CODE_SHIFT).encode()
}

pub(crate) struct AddressLayouter {
    globals_size: usize,
    code_size: usize,
}

impl AddressLayouter {
    pub(crate) fn new() -> Self {
        Self {
            globals_size: 0,
            code_size: 0,
        }
    }

    fn layout_data(&mut self, image: &mut ProcessImage) {
        let mut cursor = 0;

        for elf in image.iter_elfs_mut() {
            for section in elf.iter_sections_mut() {
                if section.perms().is_executable() {
                    continue;
                }

                section.set_vaddr(AddressSpace::Data(cursor).encode());

                for symbol in section.iter_symbols_mut() {
                    symbol.set_vaddr(AddressSpace::Data(cursor).encode());

                    for chunk in symbol.iter_chunks_mut() {
                        chunk.set_vaddr(AddressSpace::Data(cursor).encode());
                        cursor += chunk.size();
                    }
                }
            }
        }

        self.globals_size = cursor;
    }

    fn layout_code(&mut self, image: &mut ProcessImage) {
        let mut cursor = 0;

        for elf in image.iter_elfs_mut() {
            for section in elf.iter_sections_mut() {
                if !section.perms().is_executable() {
                    continue;
                }

                let section_start = cursor;
                section.set_vaddr(make_code_address(section_start));

                for symbol in section.iter_symbols_mut() {
                    let mut public_names = HashMap::new();
                    for name in symbol.public_names() {
                        let vaddr = symbol.public_name(name).unwrap();

                        for chunk in symbol.iter_chunks() {
                            if chunk.contains_address(vaddr) {
                                public_names.insert(name.clone(), chunk.id());
                                break;
                            }
                        }
                    }

                    let mut private_names = HashMap::new();
                    for name in symbol.private_names() {
                        let vaddr = symbol.private_name(name).unwrap();

                        for chunk in symbol.iter_chunks() {
                            if chunk.contains_address(vaddr) {
                                private_names.insert(name.clone(), chunk.id());
                                break;
                            }
                        }
                    }

                    let symbol_start = cursor;
                    symbol.set_vaddr(make_code_address(symbol_start));

                    for chunk in symbol.iter_chunks_mut() {
                        let chunk_start = cursor;
                        chunk.set_vaddr(make_code_address(chunk_start));

                        let ChunkContent::Code(func) = chunk.content_mut() else { unreachable!() };

                        for bb in func.cfg_mut().iter_basic_blocks_mut() {
                            bb.set_vaddr(make_code_address(cursor));
                            cursor += 1;
                        }

                        chunk.set_size(cursor - chunk_start);
                    }

                    for (name, chunk_id) in public_names {
                        let chunk = symbol.chunk(chunk_id).unwrap();
                        symbol.set_public_name(name, chunk.vaddr());
                    }

                    for (name, chunk_id) in private_names {
                        let chunk = symbol.chunk(chunk_id).unwrap();
                        symbol.set_private_name(name, chunk.vaddr());
                    }

                    symbol.set_size(cursor - symbol_start);
                }

                section.set_size(cursor - section_start);
            }
        }

        self.code_size = cursor;
    }

    pub(crate) fn layout(&mut self, image: &mut ProcessImage) {
        self.layout_data(image);
        self.layout_code(image);
    }

    pub(crate) fn globals_size(&self) -> usize {
        self.globals_size
    }

    pub(crate) fn code_size(&self) -> usize {
        self.code_size
    }
}

pub(crate) fn get_entrypoint_address(image: &ProcessImage) -> VAddr {
    let pointer = image.entrypoint();

    let chunk = image
        .elf(pointer.elf)
        .unwrap()
        .section(pointer.section)
        .unwrap()
        .symbol(pointer.symbol)
        .unwrap()
        .chunk(pointer.chunk)
        .unwrap();

    let ChunkContent::Code(func) = chunk.content() else { unreachable!() };
    let entry = func.cfg().entry();

    func.cfg().basic_block(entry).unwrap().vaddr().unwrap()
}
