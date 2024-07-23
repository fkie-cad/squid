use squid::{
    backends::clang::{
        ClangBackend,
        ClangRuntime,
        ClangRuntimeFault,
        perms::PERM_UNINIT,
    },
    event::{EVENT_BREAKPOINT, EVENT_SYSCALL, EventPool},
    frontend::{
        VAddr,
        ao::{AoError, Function, BasicBlock, Edge},
        ProcessImage,
        Symbol,
        Chunk,
        Perms,
        ChunkContent,
    },
    passes::Pass,
    riscv::{
        register::GpRegister,
        syscalls,
    },
    runtime::Runtime,
    Compiler,
    Logger,
};
use std::collections::HashSet;

struct AsanPass {
    num_redzones: usize,
    hooked_functions: HashSet<&'static str>,
    malloc: Option<usize>,
    free: Option<usize>,
    realloc: Option<usize>,
    calloc: Option<usize>,
}

impl AsanPass {
    fn new() -> Self {
        Self {
            num_redzones: 0,
            hooked_functions: HashSet::new(),
            malloc: None,
            free: None,
            realloc: None,
            calloc: None,
        }
    }

    fn build_redzone(&self, size: usize) -> Symbol {
        let mut redzone = Symbol::builder().private_name("(redzone)").size(size).vaddr(0).build().unwrap();
        let chunk = Chunk::builder().uninitialized_data(size, Perms::default()).vaddr(0).build().unwrap();
        redzone.insert_chunk(chunk);
        redzone
    }

    fn insert_redzones(&mut self, image: &mut ProcessImage) {
        let mut last_size = None;
        let elf = image.iter_elfs_mut().next().unwrap();

        for section in elf.iter_sections_mut() {
            if !section.perms().is_writable() {
                continue;
            }
            section.set_cursor(0);

            while let Some(symbol) = section.cursor_symbol() {
                self.num_redzones += 1;

                /* Calculate redzone sizes */
                let left_redzone_size = if let Some(last_size) = last_size { symbol.size().saturating_sub(last_size) } else { symbol.size() };
                let right_redzone_size = symbol.size();

                /* Left redzone */
                if left_redzone_size > 0 {
                    let redzone = self.build_redzone(left_redzone_size);
                    section.insert_symbol(redzone);
                    assert!(section.move_cursor_forward());
                }

                /* Right redzone */
                if !section.move_cursor_forward() {
                    section.move_cursor_beyond_end();
                }

                let redzone = self.build_redzone(right_redzone_size);
                section.insert_symbol(redzone);

                /* Adjust section itself */
                let new_size = section.size() + left_redzone_size + right_redzone_size;
                section.set_size(new_size);

                last_size = Some(right_redzone_size);

                if !section.move_cursor_forward() {
                    break;
                }
            }
        }
    }
    
    const EVENT_NAME_MALLOC: &'static str = "asan::malloc";
    const EVENT_NAME_FREE: &'static str = "asan::free";
    const EVENT_NAME_REALLOC: &'static str = "asan::realloc";
    const EVENT_NAME_CALLOC: &'static str = "asan::calloc";
    
    fn replace_function(&self, func: &mut Function, event_pool: &mut EventPool, event_name: &str) -> Result<usize, AoError> {
        let event_id = event_pool.add_event(event_name);

        func.cfg_mut().clear();

        let mut bb1 = BasicBlock::new();
        bb1.fire_event(event_id);

        let mut bb2 = BasicBlock::new();
        let ra = bb2.load_gp_register(GpRegister::ra);
        bb2.jump(ra)?;

        let bb2_id = func.cfg_mut().add_basic_block(bb2);
        bb1.add_edge(Edge::Next(bb2_id));
        let bb1_id = func.cfg_mut().add_basic_block(bb1);
        func.cfg_mut().set_entry(bb1_id);

        Ok(event_id.id())
    }

    fn hook_heap_functions(&mut self, image: &mut ProcessImage, event_pool: &mut EventPool) -> Result<(), AoError> {
        for elf in image.iter_elfs_mut() {
            if !elf.path().ends_with("libc.so.6") {
                continue;
            }

            for section in elf.iter_sections_mut() {
                for symbol in section.iter_symbols_mut() {
                    if symbol.name("__libc_malloc_impl").is_some() || symbol.name("__libc_malloc").is_some() {
                        let chunk = symbol.iter_chunks_mut().next().unwrap();
                        let ChunkContent::Code(func) = chunk.content_mut() else { unreachable!() };
                        let id = self.replace_function(func, event_pool, Self::EVENT_NAME_MALLOC)?;
                        self.malloc = Some(id);
                        self.hooked_functions.insert("malloc");
                    } else if symbol.name("__libc_free").is_some() {
                        let chunk = symbol.iter_chunks_mut().next().unwrap();
                        let ChunkContent::Code(func) = chunk.content_mut() else { unreachable!() };
                        let id = self.replace_function(func, event_pool, Self::EVENT_NAME_FREE)?;
                        self.free = Some(id);
                        self.hooked_functions.insert("free");
                    } else if symbol.name("__libc_realloc").is_some() {
                        let chunk = symbol.iter_chunks_mut().next().unwrap();
                        let ChunkContent::Code(func) = chunk.content_mut() else { unreachable!() };
                        let id = self.replace_function(func, event_pool, Self::EVENT_NAME_REALLOC)?;
                        self.realloc = Some(id);
                        self.hooked_functions.insert("realloc");
                    } else if symbol.name("__libc_calloc").is_some() || symbol.name("calloc").is_some() {
                        let chunk = symbol.iter_chunks_mut().next().unwrap();
                        let ChunkContent::Code(func) = chunk.content_mut() else { unreachable!() };
                        let id = self.replace_function(func, event_pool, Self::EVENT_NAME_CALLOC)?;
                        self.calloc = Some(id);
                        self.hooked_functions.insert("calloc");
                    }
                }
            }
        }
        
        Ok(())
    }
}

impl Pass for AsanPass {
    type Error = AoError;

    fn name(&self) -> String {
        "AsanPass".to_string()
    }

    fn run(&mut self, image: &mut ProcessImage, event_pool: &mut EventPool, logger: &Logger) -> Result<(), Self::Error> {
        self.insert_redzones(image);
        self.hook_heap_functions(image, event_pool)?;
        logger.info(format!("Surrounded {} symbols with redzones and hooked functions {:?}", self.num_redzones, self.hooked_functions));
        Ok(())
    }
}

impl AsanPass {
    fn handle_event(&mut self, event: usize, runtime: &mut ClangRuntime) -> Result<(), ClangRuntimeFault> {
        let event = Some(event);

        if event == self.malloc {
            let size = runtime.get_gp_register(GpRegister::a0) as usize;
            let addr = runtime.dynstore_allocate(size)?;
            runtime.set_gp_register(GpRegister::a0, addr);
        } else if event == self.free {
            let addr = runtime.get_gp_register(GpRegister::a0);
            runtime.dynstore_deallocate(addr)?;
        } else if event == self.realloc {
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
        } else if event == self.calloc {
            let a = runtime.get_gp_register(GpRegister::a0) as usize;
            let b = runtime.get_gp_register(GpRegister::a1) as usize;
            let size = a.checked_mul(b).ok_or_else(|| ClangRuntimeFault::InternalError(format!("calloc overflow: {} * {}", a, b)))?;
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
                _ => asan_pass.handle_event(event, &mut runtime).unwrap(),
            },
            Err(fault) => display_crash_report(fault, runtime),
        }
    }
}
