use crate::frontend::{
    ChunkContent,
    ProcessImage,
    VAddr,
};

pub(crate) const POINTER_TAG_SHIFT: u32 = 62;
pub(crate) const POINTER_TAG_MASK: VAddr = 0xC000000000000000;
pub(crate) const POINTER_TAG_GLOBAL: VAddr = 0;
pub(crate) const POINTER_TAG_CODE: VAddr = 0x4000000000000000;
pub(crate) const POINTER_TAG_HEAP: VAddr = 0x8000000000000000;
pub(crate) const POINTER_TAG_STACK: VAddr = 0xC000000000000000;

pub(crate) enum AddressSpace {
    Global(usize),
    Code(usize),
    Heap(usize),
    Stack(usize),
}

impl AddressSpace {
    pub(crate) fn decode(addr: VAddr) -> Self {
        match addr & POINTER_TAG_MASK {
            POINTER_TAG_GLOBAL => Self::Global((addr & !POINTER_TAG_MASK) as usize),
            POINTER_TAG_CODE => Self::Code((addr & !POINTER_TAG_MASK) as usize),
            POINTER_TAG_HEAP => Self::Heap((addr & !POINTER_TAG_MASK) as usize),
            POINTER_TAG_STACK => Self::Stack((addr & !POINTER_TAG_MASK) as usize),
            _ => unreachable!(),
        }
    }

    pub(crate) fn encode(&self) -> VAddr {
        match self {
            Self::Global(offset) => {
                let offset = *offset as VAddr;
                assert_eq!(offset & POINTER_TAG_MASK, 0);
                POINTER_TAG_GLOBAL | offset
            },
            Self::Code(index) => {
                let index = *index as VAddr;
                assert_eq!(index & POINTER_TAG_MASK, 0);
                POINTER_TAG_CODE | index
            },
            Self::Heap(offset) => {
                let offset = *offset as VAddr;
                assert_eq!(offset & POINTER_TAG_MASK, 0);
                POINTER_TAG_HEAP | offset
            },
            Self::Stack(offset) => {
                let offset = *offset as VAddr;
                assert_eq!(offset & POINTER_TAG_MASK, 0);
                POINTER_TAG_STACK | offset
            },
        }
    }
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

                section.set_vaddr(AddressSpace::Global(cursor).encode());

                for symbol in section.iter_symbols_mut() {
                    symbol.set_vaddr(AddressSpace::Global(cursor).encode());

                    for chunk in symbol.iter_chunks_mut() {
                        chunk.set_vaddr(AddressSpace::Global(cursor).encode());
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
                section.set_vaddr(AddressSpace::Code(section_start).encode());

                for symbol in section.iter_symbols_mut() {
                    let symbol_start = cursor;
                    symbol.set_vaddr(AddressSpace::Code(symbol_start).encode());

                    for chunk in symbol.iter_chunks_mut() {
                        let chunk_start = cursor;
                        chunk.set_vaddr(AddressSpace::Code(chunk_start).encode());

                        let ChunkContent::Code(func) = chunk.content_mut() else { unreachable!() };

                        for bb in func.cfg_mut().iter_basic_blocks_mut() {
                            bb.set_vaddr(AddressSpace::Code(cursor).encode());
                            cursor += 1;
                        }

                        chunk.set_size(cursor - chunk_start);
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

    let chunk = image.elf(pointer.elf).unwrap().section(pointer.section).unwrap().symbol(pointer.symbol).unwrap().chunk(pointer.chunk).unwrap();

    let ChunkContent::Code(func) = chunk.content() else { unreachable!() };
    let entry = func.cfg().entry();

    func.cfg().basic_block(entry).unwrap().vaddr().unwrap()
}
