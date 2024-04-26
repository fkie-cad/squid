use std::collections::HashMap;

use crate::frontend::{
    ao::Op,
    ChunkContent,
    FixedVec,
    Pointer,
    ProcessImage,
    VAddr,
};

fn lookup_pointer(image: &ProcessImage, pointer: &Pointer, table: &mut HashMap<Pointer, VAddr>) {
    if table.contains_key(pointer) {
        return;
    }

    let addr = match pointer {
        Pointer::Function(pointer) => {
            let chunk = image.elf(pointer.elf).unwrap().section(pointer.section).unwrap().symbol(pointer.symbol).unwrap().chunk(pointer.chunk).unwrap();

            let ChunkContent::Code(func) = chunk.content() else { unreachable!() };
            let entry = func.cfg().entry();

            func.cfg().basic_block(entry).unwrap().vaddr().unwrap()
        },
        Pointer::BasicBlock(pointer) => {
            let chunk = image.elf(pointer.elf).unwrap().section(pointer.section).unwrap().symbol(pointer.symbol).unwrap().chunk(pointer.chunk).unwrap();

            let ChunkContent::Code(func) = chunk.content() else { unreachable!() };

            func.cfg().basic_block(pointer.bb).unwrap().vaddr().unwrap()
        },
        Pointer::Global(pointer) => {
            let addr = image.elf(pointer.elf).unwrap().section(pointer.section).unwrap().symbol(pointer.symbol).unwrap().chunk(pointer.chunk).unwrap().vaddr();
            addr + pointer.offset as VAddr
        },
        Pointer::Local(_) => unreachable!(),
        Pointer::Null => 0,
    };

    table.insert(pointer.clone(), addr);
}

pub(crate) fn concretize(image: &mut ProcessImage) {
    let mut table = HashMap::<Pointer, VAddr>::new();

    /* Build lookup table for all pointers */
    for elf in image.iter_elfs() {
        for section in elf.iter_sections() {
            for symbol in section.iter_symbols() {
                for chunk in symbol.iter_chunks() {
                    match chunk.content() {
                        ChunkContent::Pointer(pointer) => {
                            lookup_pointer(image, pointer, &mut table);
                        },
                        ChunkContent::Code(func) => {
                            for bb in func.cfg().iter_basic_blocks() {
                                for op in bb.ops() {
                                    if let Op::LoadPointer {
                                        pointer,
                                        ..
                                    } = op
                                    {
                                        lookup_pointer(image, pointer, &mut table);
                                    }
                                }
                            }
                        },
                        ChunkContent::Data {
                            ..
                        } => {},
                    }
                }
            }
        }
    }

    /* Resolve every pointer */
    for elf in image.iter_elfs_mut() {
        for section in elf.iter_sections_mut() {
            let perms = section.perms();

            for symbol in section.iter_symbols_mut() {
                for chunk in symbol.iter_chunks_mut() {
                    match chunk.content_mut() {
                        ChunkContent::Pointer(pointer) => {
                            let addr = *table.get(pointer).unwrap();
                            let bytes = FixedVec::lock(addr.to_le_bytes());
                            let perms = FixedVec::lock(vec![perms; bytes.len()]);
                            chunk.set_content(ChunkContent::Data {
                                bytes,
                                perms,
                            });
                        },
                        ChunkContent::Code(func) => {
                            for bb in func.cfg_mut().iter_basic_blocks_mut() {
                                bb.set_cursor(0);

                                while let Some(op) = bb.cursor_op() {
                                    if let Op::LoadPointer {
                                        dst,
                                        pointer,
                                    } = op
                                    {
                                        let vaddr = *table.get(pointer).unwrap();
                                        bb.replace_op(Op::LoadVirtAddr {
                                            dst: *dst,
                                            vaddr,
                                        });
                                    }

                                    if !bb.move_cursor_forward() {
                                        break;
                                    }
                                }
                            }
                        },
                        ChunkContent::Data {
                            ..
                        } => {},
                    }
                }
            }
        }
    }
}
