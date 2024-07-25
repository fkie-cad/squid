use squid::{
    backends::clang::{
        perms::PERM_UNINIT,
        ClangBackend,
        ClangRuntime,
        ClangRuntimeFault,
    },
    event::{
        EVENT_BREAKPOINT,
        EVENT_SYSCALL,
    },
    frontend::VAddr,
    passes::AsanPass,
    riscv::{
        register::GpRegister,
        syscalls,
    },
    runtime::Runtime,
    Compiler,
};

fn handle_asan_event(pass: &AsanPass, event: usize, runtime: &mut ClangRuntime) -> Result<(), ClangRuntimeFault> {
    let event = Some(event);

    if event == pass.malloc_event().map(|x| x.id()) {
        let size = runtime.get_gp_register(GpRegister::a0) as usize;
        let addr = runtime.dynstore_allocate(size)?;
        runtime.set_gp_register(GpRegister::a0, addr);
    } else if event == pass.free_event().map(|x| x.id()) {
        let addr = runtime.get_gp_register(GpRegister::a0);
        runtime.dynstore_deallocate(addr)?;
    } else if event == pass.realloc_event().map(|x| x.id()) {
        let chunk = runtime.get_gp_register(GpRegister::a0) as VAddr;
        let size = runtime.get_gp_register(GpRegister::a1) as usize;

        if size == 0 {
            runtime.dynstore_deallocate(chunk)?;
            runtime.set_gp_register(GpRegister::a0, 0);
        } else if chunk == 0 {
            let addr = runtime.dynstore_allocate(size)?;
            runtime.set_gp_register(GpRegister::a0, addr);
        } else {
            let new_chunk = runtime.dynstore_reallocate(chunk, size)?;
            runtime.set_gp_register(GpRegister::a0, new_chunk);
        }
    } else if event == pass.calloc_event().map(|x| x.id()) {
        let a = runtime.get_gp_register(GpRegister::a0) as usize;
        let b = runtime.get_gp_register(GpRegister::a1) as usize;
        let size = a
            .checked_mul(b)
            .ok_or_else(|| ClangRuntimeFault::InternalError(format!("calloc overflow: {} * {}", a, b)))?;
        let addr = runtime.dynstore_allocate(size)?;
        for perm in runtime.permissions_mut(addr, size)? {
            *perm &= !PERM_UNINIT;
        }
        runtime.set_gp_register(GpRegister::a0, addr);
    } else {
        unreachable!()
    }

    Ok(())
}

fn forward_syscall(runtime: &mut ClangRuntime) -> Result<(), ClangRuntimeFault> {
    let number = runtime.get_gp_register(GpRegister::a7);

    match number {
        syscalls::exit_group => {
            let code = runtime.get_gp_register(GpRegister::a0) as i32;
            unsafe {
                libc::exit(code);
            }
        },
        syscalls::set_tid_address => {
            // Don't forward sice this syscall is not important
            runtime.set_gp_register(GpRegister::a0, 1);
        },
        syscalls::ioctl => {
            let cmd = runtime.get_gp_register(GpRegister::a1);

            match cmd {
                libc::TIOCGWINSZ => {
                    runtime.set_gp_register(GpRegister::a0, 0);
                },
                _ => todo!("ioctl {} is not implemented yet", cmd),
            }
        },
        syscalls::writev => {
            let fd = runtime.get_gp_register(GpRegister::a0) as i32;
            let iov = runtime.get_gp_register(GpRegister::a1) as VAddr;
            let iovcnt = runtime.get_gp_register(GpRegister::a2);
            let mut ret = 0;

            for i in 0..iovcnt {
                let iov = iov + i * 16;
                let iov_base = runtime.load_dword(iov)? as VAddr;
                let iov_len = runtime.load_dword(iov + 8)? as usize;
                let data = runtime.load_slice(iov_base, iov_len)?;
                ret += unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, iov_len) };
            }

            runtime.set_gp_register(GpRegister::a0, ret as u64);
        },
        syscalls::write => {
            let fd = runtime.get_gp_register(GpRegister::a0) as i32;
            let buf = runtime.get_gp_register(GpRegister::a1) as VAddr;
            let len = runtime.get_gp_register(GpRegister::a2) as usize;
            let data = runtime.load_slice(buf, len)?;
            let ret = unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, len) };
            runtime.set_gp_register(GpRegister::a0, ret as u64);
        },
        _ => todo!("Syscall {} is not implemented yet", number),
    }

    Ok(())
}

fn display_crash_report(fault: ClangRuntimeFault, runtime: ClangRuntime) -> ! {
    let raw_code = runtime.raw_return_code();
    let last_instr = runtime.get_last_instruction();

    println!("=================================================================");
    println!("ERROR: {:?} at pc={:#x}", raw_code, last_instr);
    println!("{:?}", fault);
    println!("=================================================================");

    std::process::exit(127);
}

fn parse_args() -> (String, Vec<String>) {
    let args = std::env::args();
    let mut args = args.skip(1);

    let prog = args.next().expect("No program supplied on command line");
    let args: Vec<String> = args.collect();

    (prog, args)
}

fn parse_library_path() -> Vec<String> {
    let mut ret = Vec::new();

    if let Ok(value) = std::env::var("LIBRARY_PATH") {
        ret = value.split(':').map(|x| x.to_string()).collect();
    }

    ret
}

fn parse_preload() -> Vec<String> {
    let mut ret = Vec::new();

    if let Ok(value) = std::env::var("PRELOAD") {
        ret = value.split(':').map(|x| x.to_string()).collect();
    }

    ret
}

fn main() {
    // 0) Collect arguments and environment variables
    let (prog, args) = parse_args();
    let search_paths = parse_library_path();
    let preloads = parse_preload();

    // 1) Load and lift the target binary into our custom IR
    let mut compiler = Compiler::load_elf(prog.clone(), &search_paths, &preloads).unwrap();

    // 2) Run the ASAN pass over the binary to insert redzones and interceptors for the heap functions
    let mut asan_pass = AsanPass::new();
    compiler.run_pass(&mut asan_pass).unwrap();

    // 3) AOT compile functions in IR down to native machine code by generating C code that we compile with clang
    let backend = ClangBackend::builder()
        .stack_size(2 * 1024 * 1024)
        .heap_size(16 * 1024 * 1024)
        .enable_uninit_stack(true) // MemorySanitizer
        .progname(prog) // argv[0]
        .args(args) // argv[1..]
        .source_file("./aot.c") // The AOT code goes into this file
        .update_last_instruction(true)
        .build()
        .unwrap();
    let mut runtime = compiler.compile(backend).unwrap();

    // 4) Emulate the binary and handle all runtime events
    loop {
        match runtime.run() {
            Ok(event) => match event {
                EVENT_BREAKPOINT => panic!("Hit a breakpoint"),
                EVENT_SYSCALL => forward_syscall(&mut runtime).unwrap(),
                _ => handle_asan_event(&asan_pass, event, &mut runtime).unwrap(),
            },
            Err(fault) => display_crash_report(fault, runtime),
        }
    }
}
