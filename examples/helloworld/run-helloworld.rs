use squid::{
    Compiler,
    runtime::Runtime,
    backends::multiverse::{MultiverseBackend, MultiverseRuntime, MultiverseRuntimeFault},
    event::EVENT_SYSCALL,
    riscv::register::GpRegister,
    riscv::syscalls,
    frontend::VAddr,
    passes::ImageDOTPass,
};

// Do one run of the target binary from its entrypoint to exit()
fn execute(mut runtime: MultiverseRuntime) -> Result<(), MultiverseRuntimeFault> {
    loop {
        match runtime.run()? {
            EVENT_SYSCALL => {
                let number = runtime.get_gp_register(GpRegister::a7);
                
                match number {
                    syscalls::write => {
                        // Get syscall arguments
                        let buf = runtime.get_gp_register(GpRegister::a1) as VAddr;
                        let len = runtime.get_gp_register(GpRegister::a2) as usize;
                        
                        let data = runtime.load_slice(buf, len)?;
                        let data = std::str::from_utf8(data).unwrap();
                        
                        // Do syscall action
                        print!("{}", data);
                        
                        // Set syscall return value
                        runtime.set_gp_register(GpRegister::a0, len as u64);
                    },
                    syscalls::exit_group => {
                        let code = runtime.get_gp_register(GpRegister::a0) as i8;
                        std::process::exit(code as i32);
                    },
                    _ => unreachable!(),
                }
            },
            _ => unreachable!(),
        }
    }
}

fn main() {
    let mut compiler = Compiler::load_elf("./helloworld", &[], &[]).unwrap();
    
    // this is of course optional
    compiler.run_pass(&mut ImageDOTPass::new("process_image.dot")).unwrap();
    
    let backend = MultiverseBackend::builder()
        .heap_size(0)
        .stack_size(1024 * 1024)
        .progname("helloworld")
        .source_file("./emu.c")
        .build().
        unwrap();
    let runtime = compiler.compile(backend).unwrap();
    execute(runtime).unwrap();
}
