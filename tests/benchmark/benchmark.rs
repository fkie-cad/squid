use squid::{
    backends::clang::ClangBackend,
    event::EVENT_BREAKPOINT,
    runtime::Runtime,
    Compiler,
};

#[test]
fn benchmark_emulator() {
    let compiler = Compiler::load_elf("../tests/benchmark/bench", &[], &[]).unwrap();
    let backend = ClangBackend::builder()
        .stack_size(1024 * 1024)
        .progname("bench")
        .source_file("../tests/benchmark/emu.c")
        .cflag("-Ofast")
        .cflag("-ffast-math")
        .cflag("-flto")
        .cflag("-s")
        .cflag("-fno-stack-protector")
        .cflag("-march=native")
        .cflag("-fomit-frame-pointer")
        .cflag("-g")
        .build_symbol_table(false)
        .update_pc(false)
        .update_last_instruction(false)
        .enable_uninit_stack(false)
        .build()
        .unwrap();
    let mut runtime = compiler.compile(backend).unwrap();

    let start = std::time::Instant::now();
    match runtime.run() {
        Ok(EVENT_BREAKPOINT) => {},
        e => unreachable!("{:?}", e),
    }
    let secs = start.elapsed().as_secs_f64();

    println!("{} instr/s", runtime.get_executed_instructions() as f64 / secs);
}
