use std::ops::Range;

use thiserror::Error;

use crate::{
    event::EventPool,
    frontend::{
        ao::{
            BasicBlock,
            Op,
        },
        Chunk,
        ChunkContent,
        Elf,
        HasId,
        Id,
        Perms,
        Pointer,
        ProcessImage,
        Section,
        Symbol,
        VAddr,
    },
    passes::Pass,
    Logger,
};

//TODO: meaningful error messages

struct RangeSet {
    ranges: Vec<Range<VAddr>>,
}

impl RangeSet {
    fn new() -> Self {
        Self {
            ranges: Vec::new(),
        }
    }

    fn insert(&mut self, start: VAddr, end: VAddr) -> bool {
        for range in &self.ranges {
            if range.contains(&start) || range.contains(&end) {
                return false;
            }
        }

        self.ranges.push(Range {
            start,
            end,
        });
        true
    }
}

fn verify_elf(elf: &Elf, verify_vaddr: bool) {
    assert_ne!(elf.id(), Id::default());
    //assert!(elf.path().exists());
    assert_ne!(elf.iter_sections().len(), 0);

    if verify_vaddr {
        /* Check that sections don't overlap */
        let mut set = RangeSet::new();

        for section in elf.iter_sections() {
            assert!(set.insert(section.vaddr(), section.last_addr() + 1));
        }
    }
}

fn verify_section(section: &Section, verify_vaddr: bool) {
    assert_ne!(section.id(), Id::default());
    assert_ne!(section.size(), 0);
    assert_ne!(section.iter_symbols().len(), 0);
    verify_perms(section.perms());

    if verify_vaddr {
        /* Verify layout */
        let mut cursor = section.vaddr();

        for symbol in section.iter_symbols() {
            assert_eq!(symbol.vaddr(), cursor);
            cursor += symbol.size() as VAddr;
        }

        assert_eq!(cursor, section.last_addr() + 1);
    }
}

fn verify_perms(perms: Perms) {
    assert!(!(perms.is_executable() && perms.is_writable()));
}

fn verify_symbol(symbol: &Symbol, verify_vaddr: bool) {
    assert_ne!(symbol.id(), Id::default());
    assert_ne!(symbol.size(), 0);
    assert_ne!(symbol.iter_chunks().len(), 0);

    if verify_vaddr {
        /* Verify layout */
        let mut cursor = symbol.vaddr();

        for chunk in symbol.iter_chunks() {
            assert_eq!(chunk.vaddr(), cursor);
            cursor += chunk.size() as VAddr;
        }

        assert_eq!(cursor, symbol.last_addr() + 1);

        /* Verify names */
        for name in symbol.public_names() {
            let vaddr = symbol.public_name(name).unwrap();
            assert!(symbol.contains_address(vaddr));
        }
        for name in symbol.private_names() {
            let vaddr = symbol.private_name(name).unwrap();
            assert!(symbol.contains_address(vaddr));
        }
    }
}

fn verify_chunk(chunk: &Chunk) {
    assert_ne!(chunk.id(), Id::default());
    assert_eq!(chunk.pending(), None);
    assert_ne!(chunk.size(), 0);

    match chunk.content() {
        ChunkContent::Code(func) => {
            func.cfg().verify().unwrap();

            for bb in func.cfg().iter_basic_blocks() {
                verify_basic_block(bb);
            }

            let entry = func.cfg().entry();

            if let Some(addr) = func.cfg().basic_block(entry).unwrap().vaddr() {
                assert_eq!(addr, chunk.vaddr());
            }
        },
        ChunkContent::Data {
            bytes,
            perms,
        } => {
            assert_eq!(chunk.size(), bytes.len());
            assert_eq!(bytes.len(), perms.len());

            for perm in &perms[..] {
                verify_perms(*perm);
                assert!(!perm.is_executable());
            }
        },
        ChunkContent::Pointer(_) => {},
    }
}

fn verify_basic_block(bb: &BasicBlock) {
    let mut max_var = 0;
    let mut should_end = false;

    for op in bb.ops() {
        assert!(!should_end);

        for var in op.input_variables() {
            max_var = std::cmp::max(max_var, var.id());
        }

        for var in op.output_variables() {
            max_var = std::cmp::max(max_var, var.id());
        }

        match op {
            Op::Branch {
                ..
            }
            | Op::FireEvent {
                ..
            }
            | Op::Jump {
                ..
            } => {
                should_end = true;
            },
            _ => {},
        }
    }

    assert!(max_var <= bb.num_variables());
}

fn verify_pointer(image: &ProcessImage, pointer: &Pointer) {
    match pointer {
        Pointer::Null => {},
        Pointer::Global(pointer) => {
            let chunk = image
                .elf(pointer.elf)
                .unwrap()
                .section(pointer.section)
                .unwrap()
                .symbol(pointer.symbol)
                .unwrap()
                .chunk(pointer.chunk)
                .unwrap();
            assert!(pointer.offset < chunk.size());
            assert!(matches!(chunk.content(), ChunkContent::Data { .. } | ChunkContent::Pointer(_)));
        },
        Pointer::BasicBlock(pointer) => {
            let chunk = image
                .elf(pointer.elf)
                .unwrap()
                .section(pointer.section)
                .unwrap()
                .symbol(pointer.symbol)
                .unwrap()
                .chunk(pointer.chunk)
                .unwrap();

            let ChunkContent::Code(func) = chunk.content() else {
                panic!("Code pointer does not point to a code chunk")
            };

            let _ = func.cfg().basic_block(pointer.bb).unwrap();
        },
        Pointer::Function(pointer) => {
            let chunk = image
                .elf(pointer.elf)
                .unwrap()
                .section(pointer.section)
                .unwrap()
                .symbol(pointer.symbol)
                .unwrap()
                .chunk(pointer.chunk)
                .unwrap();

            assert!(matches!(chunk.content(), ChunkContent::Code(_)));
        },
    }
}

/// The VerifyerPass is an internal pass that verifies the correctness of a process image.
/// If the process image has been incorrectly modified by external passes then this error
/// is thrown.
#[derive(Error, Debug)]
#[error("VerifyerPassError")]
pub struct VerifyerPassError;

pub struct VerifyerPass {
    verify_vaddr: bool,
}

impl VerifyerPass {
    #[allow(clippy::new_without_default)]
    pub fn new(verify_vaddr: bool) -> Self {
        Self {
            verify_vaddr,
        }
    }
}

impl Pass for VerifyerPass {
    type Error = VerifyerPassError;

    fn name(&self) -> String {
        "VerifyerPass".to_string()
    }

    fn run(
        &mut self,
        image: &mut ProcessImage,
        _event_pool: &mut EventPool,
        logger: &Logger,
    ) -> Result<(), VerifyerPassError> {
        verify_pointer(image, &Pointer::Function(image.entrypoint().clone()));

        for constructor in image.constructors() {
            verify_pointer(image, &Pointer::Function(constructor.clone()));
        }

        for elf in image.iter_elfs() {
            logger.debug(format!("Verifying {}", elf.path().file_name().unwrap().to_str().unwrap()));

            verify_elf(elf, self.verify_vaddr);

            for section in elf.iter_sections() {
                verify_section(section, self.verify_vaddr);

                for symbol in section.iter_symbols() {
                    verify_symbol(symbol, self.verify_vaddr);

                    for chunk in symbol.iter_chunks() {
                        verify_chunk(chunk);

                        match chunk.content() {
                            ChunkContent::Code(func) => {
                                assert!(section.perms().is_executable());

                                for bb in func.cfg().iter_basic_blocks() {
                                    for op in bb.ops() {
                                        #[allow(clippy::single_match)]
                                        match op {
                                            Op::LoadPointer {
                                                pointer,
                                                ..
                                            } => {
                                                verify_pointer(image, pointer);
                                            },
                                            Op::LoadVirtAddr {
                                                ..
                                            } => panic!(
                                                "Encountered a virtual address. ProcessImage must be fully symbolized"
                                            ),
                                            _ => {},
                                        }
                                    }
                                }
                            },
                            ChunkContent::Pointer(pointer) => {
                                assert!(!section.perms().is_executable());
                                verify_pointer(image, pointer);

                                /* check that basic block pointers don't point outside the function */
                                if let Pointer::BasicBlock(bb) = pointer {
                                    assert_eq!(bb.elf, elf.id());
                                    assert_eq!(bb.section, section.id());
                                    assert_eq!(bb.symbol, symbol.id());
                                    assert_eq!(bb.chunk, chunk.id());
                                }
                            },
                            ChunkContent::Data {
                                ..
                            } => {
                                assert!(!section.perms().is_executable());
                            },
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
