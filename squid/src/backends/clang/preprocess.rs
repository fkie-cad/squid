use crate::{
    backends::clang::PAGE_SIZE,
    event::EventPool,
    frontend::{
        ao::{
            events::EVENT_BREAKPOINT,
            BasicBlock,
            Edge,
            CFG,
        },
        BasicBlockPointer,
        Chunk,
        ChunkContent,
        Elf,
        FunctionPointer,
        Perms,
        Pointer,
        ProcessImage,
        Section,
        Symbol,
    },
    riscv::register::GpRegister,
};

pub(crate) fn insert_guard_pages(image: &mut ProcessImage) {
    /* Left guard page */
    let chunk = Chunk::builder().vaddr(0).uninitialized_data(PAGE_SIZE, Perms::default()).build().unwrap();

    let mut symbol = Symbol::builder().vaddr(0).size(PAGE_SIZE).build().unwrap();
    symbol.insert_chunk(chunk);

    let mut section = Section::builder().perms(Perms::default()).vaddr(0).size(PAGE_SIZE).build().unwrap();
    section.insert_symbol(symbol);

    let mut elf = Elf::builder().path("<null page>").build().unwrap();
    elf.insert_section(section);

    image.set_cursor(0);
    image.insert_elf(elf);

    /* Right guard page */
    let chunk = Chunk::builder().vaddr(0).uninitialized_data(PAGE_SIZE, Perms::default()).build().unwrap();

    let mut symbol = Symbol::builder().vaddr(0).size(PAGE_SIZE).build().unwrap();
    symbol.insert_chunk(chunk);

    let mut section = Section::builder().perms(Perms::default()).vaddr(0).size(PAGE_SIZE).build().unwrap();
    section.insert_symbol(symbol);

    let mut elf = Elf::builder().path("<guard page>").build().unwrap();
    elf.insert_section(section);

    image.move_cursor_beyond_end();
    image.insert_elf(elf);
}

pub(crate) fn insert_entrypoint(image: &mut ProcessImage, event_pool: &EventPool) {
    let mut cfg = CFG::new();
    let mut functions: Vec<FunctionPointer> = image.constructors().iter().rev().cloned().collect();
    functions.insert(0, image.entrypoint().clone());

    /* Start with the last basic block in function */
    let mut bb = BasicBlock::new();
    let event = event_pool.get_event(EVENT_BREAKPOINT).unwrap();
    bb.fire_event(event);
    let mut next_id = cfg.add_basic_block(bb);
    cfg.basic_block_mut(next_id).unwrap().add_edge(Edge::Next(next_id));
    cfg.set_entry(next_id); // temporary

    /* Inser the code into the process image */
    let chunk = Chunk::builder().vaddr(0).size(1).code(cfg).unwrap().build().unwrap();

    let mut symbol = Symbol::builder().vaddr(0).size(1).private_name("<entrypoint>").build().unwrap();
    let chunk = symbol.insert_chunk(chunk);

    let mut perms = Perms::default();
    perms.make_executable();
    let mut section = Section::builder().perms(perms).vaddr(0).size(1).build().unwrap();
    let symbol = section.insert_symbol(symbol);

    let mut elf = Elf::builder().path("<entrypoint>").build().unwrap();
    let section = elf.insert_section(section);

    let elf = image.insert_elf(elf);

    /* Continue building the function */
    let ChunkContent::Code(func) = image
        .elf_mut(elf)
        .unwrap()
        .section_mut(section)
        .unwrap()
        .symbol_mut(symbol)
        .unwrap()
        .chunk_mut(chunk)
        .unwrap()
        .content_mut()
    else {
        unreachable!()
    };

    for function in functions {
        let mut bb = BasicBlock::new();
        let ra = bb.load_pointer(Pointer::BasicBlock(BasicBlockPointer {
            elf,
            section,
            symbol,
            chunk,
            bb: next_id,
        }));
        bb.store_gp_register(GpRegister::ra, ra).unwrap();
        let pointer = bb.load_pointer(Pointer::Function(function.clone()));
        bb.jump(pointer).unwrap();
        bb.add_edge(Edge::Next(next_id));

        next_id = func.cfg_mut().add_basic_block(bb);
    }

    func.cfg_mut().set_entry(next_id);
    image.set_entrypoint(FunctionPointer {
        elf,
        section,
        symbol,
        chunk,
    });
}
