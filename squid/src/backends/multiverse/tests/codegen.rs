use crate::{
    backends::{
        multiverse::{
            JITReturnCode,
            MultiverseBackend,
            MultiverseRuntime,
            MultiverseRuntimeEvent,
            MultiverseRuntimeFault,
        },
        Backend,
    },
    event::EventPool,
    frontend::{
        ao::{
            events::EVENT_BREAKPOINT,
            BasicBlock,
            Comparison,
            Edge,
            Op,
            Signedness,
            CFG,
        },
        Chunk,
        Elf,
        FunctionPointer,
        Id,
        Perms,
        ProcessImage,
        Section,
        Symbol,
    },
    passes::{
        Pass,
        VerifyerPass,
    },
    riscv::{
        ieee754,
        register::{
            FpRegister,
            GpRegister,
        },
    },
    runtime::Runtime,
    Logger,
};

fn compile(cfg: CFG, mut pool: EventPool) -> MultiverseRuntime {
    assert_ne!(cfg.entry(), Id::default());

    let chunk = Chunk::builder().vaddr(0).size(1).code(cfg).unwrap().build().unwrap();

    let mut symbol = Symbol::builder().vaddr(0).size(1).private_name("<test>").build().unwrap();
    let chunk = symbol.insert_chunk(chunk);

    let mut perms = Perms::default();
    perms.make_executable();
    let mut section = Section::builder().perms(perms).vaddr(0).size(1).build().unwrap();
    let symbol = section.insert_symbol(symbol);

    let mut elf = Elf::builder().path("<test>").build().unwrap();
    let section = elf.insert_section(section);

    let mut image = ProcessImage::new();
    let elf = image.insert_elf(elf);

    image.set_entrypoint(FunctionPointer {
        elf,
        section,
        symbol,
        chunk,
    });

    let logger = Logger::spinner();

    VerifyerPass::new(true).run(&mut image, &mut pool, &logger).unwrap();

    let mut backend = MultiverseBackend::builder().heap_size(0).stack_size(1024 * 1024).progname("test").source_file("/tmp/test.c").build().unwrap();

    pool.add_event(EVENT_BREAKPOINT);
    backend.create_runtime(image, pool, &logger).unwrap()
}

#[test]
fn test_store_register() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();
    let mut bb = BasicBlock::new();

    let imm = bb.load_immediate(1234);
    let imm2 = bb.load_immediate(1.0f64.to_bits());
    let imm2 = bb.reinterpret_as_float64(imm2).unwrap();
    bb.store_gp_register(GpRegister::a0, imm).unwrap();
    bb.store_fp_register(FpRegister::ft0, imm2).unwrap();
    bb.fire_event(halt);

    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);
    let mut runtime = compile(cfg, pool);

    assert_eq!(runtime.get_gp_register(GpRegister::a0), 0);
    assert_eq!(runtime.get_fp_register(FpRegister::ft0), 0.0f64);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
        },
        error => panic!("{:?}", error),
    }

    assert_eq!(runtime.get_gp_register(GpRegister::a0), 1234);
    assert_eq!(runtime.get_fp_register(FpRegister::ft0), 1.0f64);
    println!("{:#x}", runtime.get_pc());
}

#[test]
fn test_next_bb() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb1 = BasicBlock::new();
    let imm = bb1.load_immediate(1);
    bb1.store_gp_register(GpRegister::a0, imm).unwrap();

    let mut bb2 = BasicBlock::new();
    let a0 = bb2.load_gp_register(GpRegister::a0);
    let imm = bb2.load_immediate(1);
    let result = bb2.add(a0, imm).unwrap();
    bb2.store_gp_register(GpRegister::a0, result).unwrap();
    bb2.fire_event(halt);

    let id2 = cfg.add_basic_block(bb2);
    bb1.add_edge(Edge::Next(id2));

    let id1 = cfg.add_basic_block(bb1);
    cfg.set_entry(id1);
    let mut runtime = compile(cfg, pool);

    assert_eq!(runtime.get_gp_register(GpRegister::a0), 0);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
        },
        error => panic!("{:?}", error),
    }

    assert_eq!(runtime.get_gp_register(GpRegister::a0), 2);
    println!("{:#x}", runtime.get_pc());
}

#[test]
fn test_next_bb_after_event() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb1 = BasicBlock::new();
    let imm = bb1.load_immediate(1);
    bb1.store_gp_register(GpRegister::a0, imm).unwrap();
    bb1.fire_event(halt);

    let mut bb2 = BasicBlock::new();
    let a0 = bb2.load_gp_register(GpRegister::a0);
    let imm = bb2.load_immediate(1);
    let result = bb2.add(a0, imm).unwrap();
    bb2.store_gp_register(GpRegister::a0, result).unwrap();
    bb2.fire_event(halt);

    let id2 = cfg.add_basic_block(bb2);
    bb1.add_edge(Edge::Next(id2));
    let id1 = cfg.add_basic_block(bb1);
    cfg.set_entry(id1);

    let mut runtime = compile(cfg, pool);

    assert_eq!(runtime.get_gp_register(GpRegister::a0), 0);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(runtime.get_gp_register(GpRegister::a0), 1);
            assert_eq!(id, halt.id());
        },
        error => panic!("{:?}", error),
    }

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(runtime.get_gp_register(GpRegister::a0), 2);
            assert_eq!(id, halt.id());
        },
        error => panic!("{:?}", error),
    }

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::End) => {},
        error => panic!("{:?}", error),
    }
}

#[test]
fn test_end_of_code() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();
    bb.fire_event(halt);

    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);
    let mut runtime = compile(cfg, pool);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
        },
        error => panic!("{:?}", error),
    }

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::End) => {},
        error => panic!("{:?}", error),
    }
}

#[test]
fn test_float64_add() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();
    let imm1 = bb.load_immediate(7.1f64.to_bits());
    let imm1 = bb.reinterpret_as_float64(imm1).unwrap();
    let imm2 = bb.load_immediate(1.9f64.to_bits());
    let imm2 = bb.reinterpret_as_float64(imm2).unwrap();
    let result = bb.add(imm1, imm2).unwrap();
    bb.store_fp_register(FpRegister::ft0, result).unwrap();
    bb.fire_event(halt);

    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);
    assert_eq!(runtime.get_fp_register(FpRegister::ft0), 0.0f64);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
        },
        error => panic!("{:?}", error),
    }

    assert_eq!(runtime.get_fp_register(FpRegister::ft0), 9.0f64);
    println!("{:#x}", runtime.get_pc());
}

#[test]
fn test_float32_add() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();
    let imm1 = bb.load_immediate(7.1f32.to_bits() as u64);
    let imm1 = bb.reinterpret_as_float32(imm1);
    let imm2 = bb.load_immediate(1.9f32.to_bits() as u64);
    let imm2 = bb.reinterpret_as_float32(imm2);
    let result = bb.add(imm1, imm2).unwrap();
    let result = bb.nan_box(result).unwrap();
    bb.store_fp_register(FpRegister::ft0, result).unwrap();
    bb.fire_event(halt);

    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);
    assert_eq!(runtime.get_fp_register(FpRegister::ft0), 0.0f64);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
        },
        error => panic!("{:?}", error),
    }

    assert_eq!(f32::from_bits(runtime.get_fp_register(FpRegister::ft0).to_bits() as u32), 9.0f32);
    println!("{:#x}", runtime.get_pc());
}

#[test]
fn test_sign_extend() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();
    let imm = bb.load_immediate(0x80u64);
    let result = bb.sign_extend(imm, 1).unwrap();
    bb.store_gp_register(GpRegister::a0, result).unwrap();
    let imm = bb.load_immediate(0x8000u64);
    let result = bb.sign_extend(imm, 2).unwrap();
    bb.store_gp_register(GpRegister::a1, result).unwrap();
    let imm = bb.load_immediate(0x80000000u64);
    let result = bb.sign_extend(imm, 4).unwrap();
    bb.store_gp_register(GpRegister::a2, result).unwrap();
    bb.fire_event(halt);

    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);
    assert_eq!(runtime.get_gp_register(GpRegister::a0), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::a1), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::a2), 0);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
        },
        error => panic!("{:?}", error),
    }

    assert_eq!(runtime.get_gp_register(GpRegister::a0), 0xFFFFFFFFFFFFFF80u64);
    assert_eq!(runtime.get_gp_register(GpRegister::a1), 0xFFFFFFFFFFFF8000u64);
    assert_eq!(runtime.get_gp_register(GpRegister::a2), 0xFFFFFFFF80000000u64);
    println!("{:#x}", runtime.get_pc());
}

#[test]
fn test_compare() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();
    let a = bb.load_immediate(-1i64 as u64);
    let b = bb.load_immediate(0);

    let result = bb.compare(a, b, Comparison::Equal).unwrap();
    bb.store_gp_register(GpRegister::t0, result).unwrap();

    let result = bb.compare(a, b, Comparison::NotEqual).unwrap();
    bb.store_gp_register(GpRegister::t1, result).unwrap();

    let result = bb.compare(a, b, Comparison::Less(false)).unwrap();
    bb.store_gp_register(GpRegister::t2, result).unwrap();

    let result = bb.compare(a, b, Comparison::Less(true)).unwrap();
    bb.store_gp_register(GpRegister::s0, result).unwrap();

    let result = bb.compare(a, b, Comparison::LessEqual(false)).unwrap();
    bb.store_gp_register(GpRegister::s1, result).unwrap();

    let result = bb.compare(a, b, Comparison::LessEqual(true)).unwrap();
    bb.store_gp_register(GpRegister::a0, result).unwrap();

    bb.fire_event(halt);

    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);
    assert_eq!(runtime.get_gp_register(GpRegister::t0), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::t1), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::t2), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::s0), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::s1), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::a0), 0);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
        },
        error => panic!("{:?}", error),
    }

    assert_eq!(runtime.get_gp_register(GpRegister::t0), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::t1), 1);
    assert_eq!(runtime.get_gp_register(GpRegister::t2), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::s0), 1);
    assert_eq!(runtime.get_gp_register(GpRegister::s1), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::a0), 1);

    println!("{:#x}", runtime.get_pc());
}

#[test]
fn test_compare_float64() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();
    let a = bb.load_immediate((-0.1f64).to_bits());
    let a = bb.reinterpret_as_float64(a).unwrap();
    let b = bb.load_immediate((-0.1f64).to_bits());
    let b = bb.reinterpret_as_float64(b).unwrap();

    let result = bb.compare(a, b, Comparison::Equal).unwrap();
    bb.store_gp_register(GpRegister::t0, result).unwrap();

    let result = bb.compare(a, b, Comparison::NotEqual).unwrap();
    bb.store_gp_register(GpRegister::t1, result).unwrap();

    let result = bb.compare(a, b, Comparison::Less(false)).unwrap();
    bb.store_gp_register(GpRegister::t2, result).unwrap();

    let result = bb.compare(a, b, Comparison::LessEqual(false)).unwrap();
    bb.store_gp_register(GpRegister::s0, result).unwrap();

    bb.fire_event(halt);

    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);
    assert_eq!(runtime.get_gp_register(GpRegister::t0), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::t1), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::t2), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::s0), 0);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
        },
        error => panic!("{:?}", error),
    }

    assert_eq!(runtime.get_gp_register(GpRegister::t0), 1);
    assert_eq!(runtime.get_gp_register(GpRegister::t1), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::t2), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::s0), 1);

    println!("{:#x}", runtime.get_pc());
}

#[test]
fn test_compare_float32() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();
    let a = bb.load_immediate((-0.1f32).to_bits() as u64);
    let a = bb.reinterpret_as_float32(a);
    let b = bb.load_immediate((-0.1f32).to_bits() as u64);
    let b = bb.reinterpret_as_float32(b);

    let result = bb.compare(a, b, Comparison::Equal).unwrap();
    bb.store_gp_register(GpRegister::t0, result).unwrap();

    let result = bb.compare(a, b, Comparison::NotEqual).unwrap();
    bb.store_gp_register(GpRegister::t1, result).unwrap();

    let result = bb.compare(a, b, Comparison::Less(false)).unwrap();
    bb.store_gp_register(GpRegister::t2, result).unwrap();

    let result = bb.compare(a, b, Comparison::LessEqual(false)).unwrap();
    bb.store_gp_register(GpRegister::s0, result).unwrap();

    bb.fire_event(halt);

    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);
    assert_eq!(runtime.get_gp_register(GpRegister::t0), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::t1), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::t2), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::s0), 0);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
        },
        error => panic!("{:?}", error),
    }

    assert_eq!(runtime.get_gp_register(GpRegister::t0), 1);
    assert_eq!(runtime.get_gp_register(GpRegister::t1), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::t2), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::s0), 1);

    println!("{:#x}", runtime.get_pc());
}

#[test]
fn test_load_memory1() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();
    let sp = bb.load_gp_register(GpRegister::sp);
    let argc = bb.load_word(sp).unwrap();
    bb.store_gp_register(GpRegister::a0, argc).unwrap();
    bb.fire_event(halt);

    let mut bb1 = BasicBlock::new();
    let sp = bb1.load_gp_register(GpRegister::sp);
    let amount = bb1.load_immediate(u64::MAX);
    let sp = bb1.add(sp, amount).unwrap();
    let argc = bb1.load_word(sp).unwrap();
    bb1.store_gp_register(GpRegister::a1, argc).unwrap();
    bb1.fire_event(halt);

    let id1 = cfg.add_basic_block(bb1);
    bb.add_edge(Edge::Next(id1));
    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);

    assert_eq!(runtime.get_gp_register(GpRegister::a0), 0);
    assert_eq!(runtime.get_gp_register(GpRegister::a1), 0);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
        },
        error => panic!("{:?}", error),
    }

    let sp = runtime.get_gp_register(GpRegister::sp);
    assert_eq!(runtime.get_gp_register(GpRegister::a0), 1);
    assert_eq!(runtime.get_gp_register(GpRegister::a1), 0);

    match runtime.run() {
        Err(MultiverseRuntimeFault::MemoryReadError(loc, 4)) => {
            assert_eq!(loc, sp - 1);
            assert_eq!(runtime.jit_return_code(), JITReturnCode::InvalidRead);
        },
        error => panic!("{:?}", error),
    }
}

#[test]
fn test_load_memory2() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();
    let offset = 1024 * 1024 * 8;

    let mut bb = BasicBlock::new();
    let sp = bb.load_gp_register(GpRegister::sp);
    let amount = bb.load_immediate(offset);
    let sp = bb.add(sp, amount).unwrap();
    let argc = bb.load_word(sp).unwrap();
    bb.store_gp_register(GpRegister::a0, argc).unwrap();
    bb.fire_event(halt);

    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);

    let sp = runtime.get_gp_register(GpRegister::sp);
    assert_eq!(runtime.get_gp_register(GpRegister::a0), 0);

    match runtime.run() {
        Err(MultiverseRuntimeFault::MemoryReadError(loc, 4)) => {
            assert_eq!(loc, sp + offset);
            assert_eq!(runtime.jit_return_code(), JITReturnCode::InvalidRead);
        },
        error => panic!("{:?}", error),
    }
}

#[test]
/// dirty bit mechanic works
fn test_store_memory() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();
    let sp = bb.load_gp_register(GpRegister::sp);
    let value = bb.load_immediate(0xFF);
    bb.store_byte(sp, value).unwrap();
    bb.store_byte(sp, value).unwrap();
    bb.fire_event(halt);

    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);

    runtime.stack().dump_stack();

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
        },
        error => panic!("{:?}", error),
    }

    runtime.stack().dump_stack();
}

#[test]
/// Clearing uninit bits works
fn test_store_memory2() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb1 = BasicBlock::new();
    let sp = bb1.load_gp_register(GpRegister::sp);
    let amount = bb1.load_immediate(u64::MAX);
    let sp = bb1.add(sp, amount).unwrap();
    let value = bb1.load_immediate(2);
    bb1.store_byte(sp, value).unwrap();
    let value = bb1.load_word(sp).unwrap();
    bb1.store_gp_register(GpRegister::a0, value).unwrap();
    bb1.fire_event(halt);

    let id = cfg.add_basic_block(bb1);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);

    assert_eq!(runtime.get_gp_register(GpRegister::a0), 0);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
            assert_eq!(runtime.get_gp_register(GpRegister::a0), 0x0102);
        },
        error => panic!("{:?}", error),
    }
}

#[test]
/// Storing dwords works
fn test_store_memory3() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb1 = BasicBlock::new();
    let sp = bb1.load_gp_register(GpRegister::sp);
    let amount = bb1.load_immediate(u64::MAX - (128 - 1));
    let sp = bb1.add(sp, amount).unwrap();
    let value = bb1.load_immediate(1234);
    bb1.store_dword(sp, value).unwrap();
    let value = bb1.load_dword(sp).unwrap();
    bb1.store_gp_register(GpRegister::a0, value).unwrap();
    bb1.fire_event(halt);

    let id = cfg.add_basic_block(bb1);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);

    assert_eq!(runtime.get_gp_register(GpRegister::a0), 0);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
            assert_eq!(runtime.get_gp_register(GpRegister::a0), 1234);
        },
        error => panic!("{:?}", error),
    }
}

#[test]
/// Storing words works
fn test_store_memory4() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb1 = BasicBlock::new();
    let sp = bb1.load_gp_register(GpRegister::sp);
    let amount = bb1.load_immediate(u64::MAX - (128 - 1));
    let sp = bb1.add(sp, amount).unwrap();
    let value = bb1.load_immediate(u64::MAX);
    bb1.store_dword(sp, value).unwrap();
    let value = bb1.load_immediate(0x1234);
    bb1.store_word(sp, value).unwrap();
    let value = bb1.load_dword(sp).unwrap();
    bb1.store_gp_register(GpRegister::a0, value).unwrap();
    bb1.fire_event(halt);

    let id = cfg.add_basic_block(bb1);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);

    assert_eq!(runtime.get_gp_register(GpRegister::a0), 0);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
            assert_eq!(runtime.get_gp_register(GpRegister::a0), 0xFFFFFFFF00001234);
        },
        error => panic!("{:?}", error),
    }
}

#[test]
/// Storing words works
fn test_store_memory5() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb1 = BasicBlock::new();
    let sp = bb1.load_gp_register(GpRegister::sp);
    let amount = bb1.load_immediate(u64::MAX - (128 - 1));
    let sp = bb1.add(sp, amount).unwrap();
    let value = bb1.load_immediate(u64::MAX);
    bb1.store_dword(sp, value).unwrap();
    let value = bb1.load_immediate(0x12);
    bb1.store_hword(sp, value).unwrap();
    let value = bb1.load_dword(sp).unwrap();
    bb1.store_gp_register(GpRegister::a0, value).unwrap();
    bb1.fire_event(halt);

    let id = cfg.add_basic_block(bb1);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);

    assert_eq!(runtime.get_gp_register(GpRegister::a0), 0);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
            assert_eq!(runtime.get_gp_register(GpRegister::a0), 0xFFFFFFFFFFFF0012);
        },
        error => panic!("{:?}", error),
    }

    runtime.stack().dump_stack();
}

#[test]
fn test_float32_sub() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();
    let imm1 = bb.load_immediate(9.0f32.to_bits() as u64);
    let imm1 = bb.reinterpret_as_float32(imm1);
    let imm2 = bb.load_immediate(1.9f32.to_bits() as u64);
    let imm2 = bb.reinterpret_as_float32(imm2);
    let result = bb.sub(imm1, imm2).unwrap();
    let result = bb.nan_box(result).unwrap();
    bb.store_fp_register(FpRegister::ft0, result).unwrap();
    bb.fire_event(halt);

    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);
    assert_eq!(runtime.get_fp_register(FpRegister::ft0), 0.0f64);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
        },
        error => panic!("{:?}", error),
    }

    assert_eq!(f32::from_bits(runtime.get_fp_register(FpRegister::ft0).to_bits() as u32), 7.1f32);
    println!("{:#x}", runtime.get_pc());
}

#[test]
fn test_event_channel() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let add = pool.add_event("ADD");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();
    let imm1 = bb.load_immediate(7.1f64.to_bits() as u64);
    let imm2 = bb.load_immediate(1.9f64.to_bits() as u64);
    bb.push_event_args([imm1, imm2]);
    bb.fire_event(add);

    let mut bb1 = BasicBlock::new();
    let result = bb1.collect_event_returns(1);
    let result = bb1.reinterpret_as_float64(result[0]).unwrap();
    bb1.store_fp_register(FpRegister::ft0, result).unwrap();
    bb1.fire_event(halt);

    let id1 = cfg.add_basic_block(bb1);
    bb.add_edge(Edge::Next(id1));
    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);
    assert_eq!(runtime.get_fp_register(FpRegister::ft0), 0.0f64);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, add.id());
            let event_channel = runtime.event_channel();
            assert_eq!(event_channel.len(), 2);
            let a = f64::from_bits(event_channel[0]);
            let b = f64::from_bits(event_channel[1]);
            let result = a + b;
            assert!(runtime.event_channel_mut(3).is_err());
            runtime.event_channel_mut(1).unwrap()[0] = result.to_bits();
        },
        error => panic!("{:?}", error),
    }

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
        },
        error => panic!("{:?}", error),
    }

    assert_eq!(runtime.get_fp_register(FpRegister::ft0), 9.0f64);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::End) => {},
        error => panic!("{:?}", error),
    }
}

#[test]
fn test_event_channel_error() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb1 = BasicBlock::new();
    let result = bb1.collect_event_returns(1);
    let result = bb1.reinterpret_as_float64(result[0]).unwrap();
    bb1.store_fp_register(FpRegister::ft0, result).unwrap();
    bb1.fire_event(halt);

    let id1 = cfg.add_basic_block(bb1);
    cfg.set_entry(id1);

    let mut runtime = compile(cfg, pool);

    match runtime.run() {
        Err(MultiverseRuntimeFault::InvalidEventChannel(1, 0)) => {},
        error => panic!("{:?}", error),
    }

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::End) => {},
        error => panic!("{:?}", error),
    }
}

#[test]
fn test_min() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();
    let a = bb.load_immediate(u64::MAX);
    let b = bb.load_immediate(0);
    let result = bb.minimum_number(a, b, Signedness::Unsigned).unwrap();
    bb.store_gp_register(GpRegister::a0, result).unwrap();
    let result = bb.minimum_number(a, b, Signedness::Signed).unwrap();
    bb.store_gp_register(GpRegister::a1, result).unwrap();
    bb.fire_event(halt);

    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
            assert_eq!(runtime.get_gp_register(GpRegister::a0), 0);
            assert_eq!(runtime.get_gp_register(GpRegister::a1), u64::MAX);
        },
        error => panic!("{:?}", error),
    }

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::End) => {},
        error => panic!("{:?}", error),
    }
}

#[test]
fn test_max() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();
    let a = bb.load_immediate(u64::MAX);
    let b = bb.load_immediate(0);
    let result = bb.maximum_number(a, b, Signedness::Unsigned).unwrap();
    bb.store_gp_register(GpRegister::a0, result).unwrap();
    let result = bb.maximum_number(a, b, Signedness::Signed).unwrap();
    bb.store_gp_register(GpRegister::a1, result).unwrap();
    bb.fire_event(halt);

    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
            assert_eq!(runtime.get_gp_register(GpRegister::a0), u64::MAX);
            assert_eq!(runtime.get_gp_register(GpRegister::a1), 0);
        },
        error => panic!("{:?}", error),
    }

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::End) => {},
        error => panic!("{:?}", error),
    }
}

#[test]
fn test_nan_box() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();
    let a = bb.load_immediate(0.1f32.to_bits() as u64);
    let a = bb.reinterpret_as_float32(a);
    let a = bb.nan_box(a).unwrap();
    bb.store_fp_register(FpRegister::ft0, a).unwrap();
    bb.fire_event(halt);

    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
            let value = runtime.get_fp_register(FpRegister::ft0);
            assert_eq!(f32::from_bits(value.to_bits() as u32), 0.1f32);
            assert_eq!(value.to_bits() & ieee754::NAN_BOX, ieee754::NAN_BOX);
        },
        error => panic!("{:?}", error),
    }

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::End) => {},
        error => panic!("{:?}", error),
    }
}

#[test]
fn test_muladd() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();
    let a = bb.load_immediate(2.0f64.to_bits());
    let a = bb.reinterpret_as_float64(a).unwrap();
    let b = bb.load_immediate(0.5f64.to_bits());
    let b = bb.reinterpret_as_float64(b).unwrap();
    let c = bb.load_immediate(1.0f64.to_bits());
    let c = bb.reinterpret_as_float64(c).unwrap();
    let d = bb.multiply_add(a, b, c).unwrap();
    bb.store_fp_register(FpRegister::ft0, d).unwrap();
    bb.fire_event(halt);

    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
            let value = runtime.get_fp_register(FpRegister::ft0);
            assert_eq!(value, 2.0f64);
        },
        error => panic!("{:?}", error),
    }
}

#[test]
fn test_negate() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();

    let a = bb.load_immediate(1.0f64.to_bits());
    let a = bb.reinterpret_as_float64(a).unwrap();
    let a = bb.negate(a);
    bb.store_fp_register(FpRegister::ft0, a).unwrap();

    let a = bb.load_immediate(1.0f32.to_bits() as u64);
    let a = bb.reinterpret_as_float32(a);
    let a = bb.negate(a);
    let a = bb.nan_box(a).unwrap();
    bb.store_fp_register(FpRegister::ft1, a).unwrap();

    bb.fire_event(halt);

    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
            assert_eq!(runtime.get_fp_register(FpRegister::ft0), -1.0f64);
            assert_eq!(f32::from_bits(runtime.get_fp_register(FpRegister::ft1).to_bits() as u32), -1.0f32);
        },
        error => panic!("{:?}", error),
    }
}

#[test]
fn test_sqrt() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();

    let a = bb.load_immediate(9.0f64.to_bits());
    let a = bb.reinterpret_as_float64(a).unwrap();
    let a = bb.sqrt(a).unwrap();
    bb.store_fp_register(FpRegister::ft0, a).unwrap();

    let a = bb.load_immediate(9.0f32.to_bits() as u64);
    let a = bb.reinterpret_as_float32(a);
    let a = bb.sqrt(a).unwrap();
    let a = bb.nan_box(a).unwrap();
    bb.store_fp_register(FpRegister::ft1, a).unwrap();

    bb.fire_event(halt);

    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
            assert_eq!(runtime.get_fp_register(FpRegister::ft0), 3.0f64);
            assert_eq!(f32::from_bits(runtime.get_fp_register(FpRegister::ft1).to_bits() as u32), 3.0f32);
        },
        error => panic!("{:?}", error),
    }
}

fn run_single_classify32(value: f32) {
    println!("Classifying {} ({:#x})", value, value.to_bits());

    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();

    let a = bb.load_immediate(value.to_bits() as u64);
    let a = bb.reinterpret_as_float32(a);
    let result = bb.classify(a).unwrap();
    bb.store_gp_register(GpRegister::a0, result).unwrap();
    bb.fire_event(halt);

    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
            assert_eq!(runtime.get_gp_register(GpRegister::a0), ieee754::classify(value),);
        },
        error => panic!("{:?}", error),
    }
}

#[test]
fn test_classify_float32() {
    run_single_classify32(0.1f32);
    run_single_classify32(-0.1f32);
    run_single_classify32(-0.1f32);

    /*
    run_single_classify32(f32::INFINITY);
    run_single_classify32(f32::NEG_INFINITY);
    run_single_classify32(0.0f32);
    run_single_classify32(-0.0f32);
    run_single_classify32(f32::from_bits(0x7f800000));
    run_single_classify32(f32::from_bits(0x7fc00000));*/
}

fn run_single_classify64(value: f64) {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();

    let a = bb.load_immediate(value.to_bits());
    let a = bb.reinterpret_as_float64(a).unwrap();
    let result = bb.classify(a).unwrap();
    bb.store_gp_register(GpRegister::a0, result).unwrap();
    bb.fire_event(halt);

    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
            assert_eq!(runtime.get_gp_register(GpRegister::a0), ieee754::classify(value),);
        },
        error => panic!("{:?}", error),
    }
}

#[test]
fn test_classify_float64() {
    run_single_classify64(0.1f64);
    run_single_classify64(-0.1f64);
    run_single_classify64(f64::INFINITY);
    run_single_classify64(f64::NEG_INFINITY);
    run_single_classify64(0.0f64);
    run_single_classify64(-0.0f64);
    run_single_classify64(f64::from_bits(0x7f800000));
    run_single_classify64(f64::from_bits(0x7fc00000));
}

#[test]
fn test_convert_integer32() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();

    let a = bb.load_immediate(9.0f64.to_bits());
    let a = bb.reinterpret_as_float64(a).unwrap();
    let a = bb.convert_to_integer32(a, Signedness::Unsigned);
    bb.store_gp_register(GpRegister::a0, a).unwrap();

    let a = bb.load_immediate((-9.0f64).to_bits());
    let a = bb.reinterpret_as_float64(a).unwrap();
    let a = bb.convert_to_integer32(a, Signedness::Unsigned);
    bb.store_gp_register(GpRegister::a1, a).unwrap();

    bb.fire_event(halt);

    let id = cfg.add_basic_block(bb);
    cfg.set_entry(id);

    let mut runtime = compile(cfg, pool);

    assert_eq!(runtime.get_gp_register(GpRegister::a1), 0);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
            assert_eq!(runtime.get_gp_register(GpRegister::a0), 9);
            println!("{}", runtime.get_gp_register(GpRegister::a1));
        },
        error => panic!("{:?}", error),
    }
}

#[test]
fn test_bb_split() {
    let mut pool = EventPool::new();
    let halt = pool.add_event("HALT");
    let pause = pool.add_event("PAUSE");
    let mut cfg = CFG::new();

    let mut bb = BasicBlock::new();
    let imm1 = bb.load_immediate(1234);
    let imm2 = bb.load_immediate(2345);
    let result = bb.add(imm1, imm2).unwrap();
    bb.store_gp_register(GpRegister::a0, result).unwrap();
    bb.fire_event(halt);

    bb.set_cursor(0);

    while let Some(op) = bb.cursor_op() {
        if matches!(op, Op::Add { .. }) {
            break;
        } else {
            bb.move_cursor_forward();
        }
    }

    let bb1 = bb.split();

    bb.move_cursor_beyond_end();
    bb.fire_event(pause);

    let id = cfg.add_basic_block(bb1);
    bb.add_edge(Edge::Next(id));
    let entry = cfg.add_basic_block(bb);
    cfg.set_entry(entry);

    let mut runtime = compile(cfg, pool);

    assert_eq!(runtime.get_gp_register(GpRegister::a0), 0);

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, pause.id());
            assert_eq!(runtime.get_gp_register(GpRegister::a0), 0);
            println!("pc = {:#x}", runtime.get_pc());
        },
        error => panic!("{:?}", error),
    }

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::Event(id)) => {
            assert_eq!(id, halt.id());
            assert_eq!(runtime.get_gp_register(GpRegister::a0), 3579);
            println!("pc = {:#x}", runtime.get_pc());
        },
        error => panic!("{:?}", error),
    }

    match runtime.run() {
        Ok(MultiverseRuntimeEvent::End) => {},
        error => panic!("{:?}", error),
    }
}
