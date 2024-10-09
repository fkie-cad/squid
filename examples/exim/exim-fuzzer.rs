use squid::{
    Compiler,
    backends::clang::{ClangBackend, ClangRuntime, ClangRuntimeFault},
    runtime::Runtime,
    event::{EVENT_SYSCALL, EVENT_BREAKPOINT},
    riscv::register::GpRegister,
    riscv::syscalls,
    passes::{AsanPass, BreakpointPass},
};

const EVENT_MALLOC: usize = 3;
const EVENT_CALLOC: usize = 2;
const EVENT_REALLOC: usize = 5;
const EVENT_FREE: usize = 4;

fn run(runtime: &mut ClangRuntime) -> Result<(), ClangRuntimeFault> {
    loop {
        match runtime.run()? {
            EVENT_BREAKPOINT => {
                let pc = runtime.get_pc();
                let addr = runtime.get_last_instruction();
                let symbols = runtime.lookup_symbol_from_address(pc);
                println!("pc={:#x} addr={:#x} {:?}", pc, addr, symbols);
            },
            EVENT_SYSCALL => {
                let number = runtime.get_gp_register(GpRegister::a7);

                match number {
                    syscalls::set_tid_address => {
                        runtime.set_gp_register(GpRegister::a0, 1);
                    },
                    _ => todo!("syscall: {}", number),
                }
            },
            EVENT_FREE => {
                let addr = runtime.get_gp_register(GpRegister::a0);
                runtime.dynstore_deallocate(addr)?;
            },
            event => todo!("event: {}", event),
        }
    }
}

fn main() {
    let mut compiler = Compiler::loader()
        .binary("./dist/exim")
        .search_path("./dist/lib")
        .ignore_missing_dependencies(true)
        .load()
        .unwrap();

    let mut asan_pass = AsanPass::new();
    compiler.run_pass(&mut asan_pass).unwrap();
    assert_eq!(asan_pass.malloc_event().unwrap().id(), EVENT_MALLOC);
    assert_eq!(asan_pass.calloc_event().unwrap().id(), EVENT_CALLOC);
    assert_eq!(asan_pass.realloc_event().unwrap().id(), EVENT_REALLOC);
    assert_eq!(asan_pass.free_event().unwrap().id(), EVENT_FREE);

    let mut breakpoint_pass = BreakpointPass::new();
    compiler.run_pass(breakpoint_pass.all()).unwrap();
    
    let backend = ClangBackend::builder()
        .build_symbol_table(true)
        .heap_size(8 * 1024 * 1024)
        .stack_size(2 * 1024 * 1024)
        .update_last_instruction(cfg!(debug_assertions))
        .update_pc(true)
        .progname("exim")
        .source_file("aot.c")
        .cflag("-O0")
        .cflag("-march=native")
        .cflag("-fno-inline")
        //.cflag("-g")
        .cflag("-Wall")
        .cflag("-Wextra")
        .cflag("-Wpedantic")
        .cflag("-Werror")
        .cflag("-fno-omit-frame-pointer")
        .cflag("-Wno-nan-infinity-disabled")
        .build()
        .unwrap();

    let mut runtime = compiler.compile(backend).unwrap();
    
    let sym = runtime.lookup_symbol_from_address(1436827);
    println!("err: {:?}", sym);
    let sym = runtime.lookup_symbol_from_address(1436827 - 1);
    println!("prev: {:?}", sym);
    
    let err = run(&mut runtime);
    
    println!("last instr: {:#x}", runtime.get_last_instruction());
    println!("last pc: {:#x}", runtime.get_pc());
    err.unwrap();
}
