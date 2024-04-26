use crate::{
    frontend::{
        ao::BasicBlock,
        ChunkContent,
        Elf,
        HasId,
        Pointer,
    },
    riscv::register::GpRegister,
};

pub(crate) struct HandleRelaxationPass {}

impl HandleRelaxationPass {
    #[allow(clippy::new_without_default)]
    pub(crate) fn new() -> Self {
        Self {}
    }

    pub(crate) fn run(&mut self, elf: &mut Elf) -> Result<(), String> {
        for section in elf.iter_sections_mut() {
            if !section.perms().is_executable() {
                continue;
            }

            for symbol in section.iter_symbols_mut() {
                if symbol.private_name("load_gp").is_some() {
                    let mut id = None;

                    for chunk in symbol.iter_chunks() {
                        assert!(id.is_none());
                        id = Some(chunk.id());
                    }

                    let id = id.unwrap();

                    let chunk = symbol.chunk_mut(id).unwrap();
                    let addr = chunk.vaddr();
                    let ChunkContent::Code(func) = chunk.content_mut() else { unreachable!() };

                    func.cfg_mut().clear();

                    let mut bb = BasicBlock::at_vaddr(addr);
                    let null = bb.load_pointer(Pointer::Null);
                    bb.store_gp_register(GpRegister::gp, null).unwrap();
                    let ra = bb.load_gp_register(GpRegister::ra);
                    bb.jump(ra).unwrap();

                    let id = func.cfg_mut().add_basic_block(bb);
                    func.cfg_mut().set_entry(id);
                }
            }
        }

        Ok(())
    }
}
