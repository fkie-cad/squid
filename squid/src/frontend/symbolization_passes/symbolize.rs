use std::collections::HashMap;

use crate::frontend::{
    ao::Op,
    BasicBlockPointer,
    ChunkContent,
    Elf,
    FunctionPointer,
    GlobalPointer,
    HasId,
    Pointer,
    Relocation,
    VAddr,
};

pub(crate) struct SymbolizerPass {
    addr_map: HashMap<VAddr, Pointer>,
}

impl SymbolizerPass {
    #[allow(clippy::new_without_default)]
    pub(crate) fn new() -> Self {
        Self {
            addr_map: HashMap::new(),
        }
    }

    fn resolve_address(&mut self, elf: &Elf, vaddr: VAddr) {
        let mut pointer = None;

        if self.addr_map.contains_key(&vaddr) {
            return;
        }

        for section in elf.iter_sections() {
            if !section.contains_address(vaddr) {
                continue;
            }

            for symbol in section.iter_symbols() {
                if !symbol.contains_address(vaddr) {
                    continue;
                }

                for chunk in symbol.iter_chunks() {
                    if !chunk.contains_address(vaddr) {
                        continue;
                    }

                    if chunk.pending().is_some() {
                        assert!(!section.perms().is_executable());

                        let offset = vaddr - chunk.vaddr();
                        assert!(pointer.is_none());
                        pointer = Some(Pointer::Global(GlobalPointer {
                            elf: elf.id(),
                            section: section.id(),
                            symbol: symbol.id(),
                            chunk: chunk.id(),
                            offset: offset as usize,
                        }));
                    } else {
                        match chunk.content() {
                            ChunkContent::Code(func) => {
                                let entry = func.cfg().entry();

                                for bb in func.cfg().iter_basic_blocks() {
                                    if bb.vaddr() == Some(vaddr) {
                                        assert!(pointer.is_none());

                                        if bb.id() == entry {
                                            pointer = Some(Pointer::Function(FunctionPointer {
                                                elf: elf.id(),
                                                section: section.id(),
                                                symbol: symbol.id(),
                                                chunk: chunk.id(),
                                            }));
                                        } else {
                                            pointer = Some(Pointer::BasicBlock(BasicBlockPointer {
                                                elf: elf.id(),
                                                section: section.id(),
                                                symbol: symbol.id(),
                                                chunk: chunk.id(),
                                                bb: bb.id(),
                                            }));
                                        }
                                    }
                                }
                            },
                            ChunkContent::Data {
                                ..
                            } => {
                                let offset = vaddr - chunk.vaddr();
                                assert!(pointer.is_none());
                                pointer = Some(Pointer::Global(GlobalPointer {
                                    elf: elf.id(),
                                    section: section.id(),
                                    symbol: symbol.id(),
                                    chunk: chunk.id(),
                                    offset: offset as usize,
                                }));
                            },
                            ChunkContent::Pointer(_) => {
                                assert_eq!(vaddr, chunk.vaddr());
                                assert!(pointer.is_none());
                                pointer = Some(Pointer::Global(GlobalPointer {
                                    elf: elf.id(),
                                    section: section.id(),
                                    symbol: symbol.id(),
                                    chunk: chunk.id(),
                                    offset: 0,
                                }));
                            },
                        }
                    }
                }
            }
        }

        if let Some(pointer) = pointer {
            self.addr_map.insert(vaddr, pointer);
        } else {
            panic!("Unable to symbolize {:#x} in {}", vaddr, elf.path().display());
        }
    }

    fn collect_addresses(&mut self, elf: &Elf) {
        for section in elf.iter_sections() {
            for symbol in section.iter_symbols() {
                for chunk in symbol.iter_chunks() {
                    if let Some(reloc) = chunk.pending() {
                        match reloc {
                            Relocation::Offset(addr) => self.resolve_address(elf, *addr as VAddr),
                            _ => panic!("Encountered an unresolved symbol import in symbolizer pass"),
                        }
                    } else if let ChunkContent::Code(func) = chunk.content() {
                        for bb in func.cfg().iter_basic_blocks() {
                            for op in bb.ops() {
                                if let Op::LoadVirtAddr {
                                    vaddr,
                                    ..
                                } = op
                                {
                                    self.resolve_address(elf, *vaddr);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn rewrite_addresses(&self, elf: &mut Elf) {
        for section in elf.iter_sections_mut() {
            for symbol in section.iter_symbols_mut() {
                for chunk in symbol.iter_chunks_mut() {
                    if let Some(reloc) = chunk.pending() {
                        let pointer = match reloc {
                            Relocation::Offset(addr) => self.addr_map.get(&(*addr as VAddr)).unwrap().clone(),
                            _ => panic!("Encountered an unresolved symbol import in symbolizer pass"),
                        };
                        chunk.resolve(pointer);
                    } else if let ChunkContent::Code(func) = chunk.content_mut() {
                        for bb in func.cfg_mut().iter_basic_blocks_mut() {
                            bb.set_cursor(0);

                            while let Some(op) = bb.cursor_op() {
                                if let Op::LoadVirtAddr {
                                    dst,
                                    vaddr,
                                } = op
                                {
                                    let pointer = self.addr_map.get(vaddr).unwrap().clone();
                                    bb.replace_op(Op::LoadPointer {
                                        dst: *dst,
                                        pointer,
                                    });
                                }

                                if !bb.move_cursor_forward() {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn check(&self, elf: &Elf) {
        for section in elf.iter_sections() {
            for symbol in section.iter_symbols() {
                for chunk in symbol.iter_chunks() {
                    assert!(chunk.pending().is_none());
                }
            }
        }
    }

    pub(crate) fn run(&mut self, elf: &mut Elf) -> Result<(), String> {
        self.collect_addresses(elf);
        self.rewrite_addresses(elf);
        self.check(elf);
        Ok(())
    }
}
