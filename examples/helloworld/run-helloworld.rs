use squid::{
    backends::clang::{
        ClangBackend,
        ClangRuntime,
        ClangRuntimeFault,
    },
    event::EVENT_SYSCALL,
    frontend::VAddr,
    passes::ImageDOTPass,
    riscv::{
        register::GpRegister,
        syscalls,
    },
    runtime::Runtime,
    Compiler,
};

// Do one run of the target binary from entrypoint to exit() and forward all system calls
fn execute(mut runtime: ClangRuntime) -> Result<(), ClangRuntimeFault> {
    loop {
        match runtime.run()? {
            EVENT_SYSCALL => {
                let number = runtime.get_gp_register(GpRegister::a7);

                match number {
                    syscalls::write => {
                        // Get syscall arguments
                        let fd = runtime.get_gp_register(GpRegister::a0) as i32;
                        let buf = runtime.get_gp_register(GpRegister::a1) as VAddr;
                        let len = runtime.get_gp_register(GpRegister::a2) as usize;
                        
                        // Do the syscall
                        let data = runtime.load_slice(buf, len)?;
                        let ret = unsafe {
                            libc::write(
                                fd,
                                data.as_ptr() as *const libc::c_void,
                                len
                            )
                        };
                        
                        // Set syscall return value
                        runtime.set_gp_register(GpRegister::a0, ret as u64);
                    },
                    syscalls::exit_group => {
                        let code = runtime.get_gp_register(GpRegister::a0) as i32;
                        unsafe { 
                            libc::exit(code);
                        }
                    },
                    _ => unreachable!(),
                }
            },
            _ => unreachable!(),
        }
    }
}

fn main() {
    // 1) Load the target binary
    let mut compiler = Compiler::load_elf("./helloworld", &[], &[]).unwrap();

    // 2) Run passes over binary
    compiler.run_pass(&mut ImageDOTPass::new("process_image.dot")).unwrap();

    // 3) AOT compile code in binary for fast emulation
    let backend = ClangBackend::builder()
        .stack_size(1024 * 1024)
        .progname("helloworld") // argv[0]
        .source_file("./emu.c") // The AOT code goes into this file
        .build()
        .unwrap();
    let runtime = compiler.compile(backend).unwrap();
    
    // 4) Emulate the binary
    execute(runtime).unwrap();
}
