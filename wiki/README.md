# Overview

This page briefly introduces the most important aspects of `squid`.   
Since `squid` is a RISC-V emulator with AOT-compilation its usage can be divided into 3 phases:

1. Compiling the target to RISC-V
2. Doing the AOT compilation
    1. Loading the binary and all its dependencies
    2. Running passes to modify code or data
    3. Compiling the code to the native ISA
3. Emulating the target by running the compiled code

Each phase is explained in more detail below.

## Compiling the target
Follow the instructions in [TOOLCHAIN.md](./TOOLCHAIN.md) to compile your target to RISC-V.
Please note, that you also need to compile all of the targets dependencies to RISC-V.

## Loading the binary
Once you have compiled the binary and all it's dependencies to RISC-V, the next step is to create the so-called "process image".   
The process image is the result of ELF-loading the fuzz target and lifting all functions into an IR.
All dependencies of the program are collected, symbol imports are being resolved and all pointers are "symbolized" in
a manner similar to [RetroWrite](https://github.com/HexHive/RetroWrite).
This creates an in-memory data structure that makes all functions and global variables of the loaded ELF files available for
inspection and modification. Because of the symbolization we can freely modify everything without having to worry about
invalidating references or offsets.

Load your binary like so:
```rs
let mut compiler = Compiler::load_elf(
    // The binary that we want to emulate
    "/path/to/binary",
    
    // Directories that contain the dependencies of the binary similar to LD_LIBRARY_PATH
    &[
        "/path/with/deps",
    ],
    
    // List of shared objects to preload similar to LD_PRELOAD
    &[
        "/path/to/library.so",
    ]
).expect("Loading binary failed");
```

For more information about the process image, see [PROCESS\_IMAGE](./PROCESS_IMAGE/).

## Running Passes
Once the process image has been created, we can run passes to modify functions or data. 
A pass in `squid` is anything that implements the `Pass` trait. Otherwise, it functions exactly
like an LLVM pass.

```rs
struct MyPass;

impl Pass for MyPass {
    fn name(&self) -> String {
        // return the name of this pass here
    }

    fn run(&mut self, image: &mut ProcessImage, event_pool: &mut EventPool, logger: &Logger) -> Result<(), String> {
        // modify functions or data in the process image here
    }
}

// Run the pass with the compiler
compiler.run_pass(&mut MyPass {}).expect("Pass had an error");
```

## Creating a Runtime
The final step before emulation is to AOT-compile all functions to the host ISA.
This is the responsibility of a "backend".
The backend receives a process image and produces a "runtime" that interfaces with the target program. 
In a similar fashion like before, a backend is anything that implements the `Backend` trait and a runtime
is anything that implements the `Runtime` trait.

Currently, `squid` comes with the `MultiverseBackend` and the `MultiverseRuntime`:
```rs
// Create the backend responsible for compilation
let backend = MultiverseBackend::builder()
    .heap_size(1 * 1024 * 1024)             // Size of the heap region
    .stack_size(1 * 1024 * 1024)            // Size of the stack region
    .progname("my-fuzz-target")             // argv[0]
    .arg("--with-bugs-pls")                 // argv[1]
    .build()
    .expect("Could not configure backend");

// Start AOT-compilation with the given backend and get a runtime in return
let runtime = compiler.compile(backend).expect("Backend had an error");
```

## Running the target
Once we have obtained the runtime, we can start interacting with the program.    
The runtime gives us access to the registers and memory, it lets us create snapshots, restore
snapshots and of course run our target with the `Runtime::run` method.   
Running the target will throw certain events like system calls or breakpoints that
must be handled by the harness.
It is also possible to throw custom events that can be created inside passes.

Run the target like so:
```rs
loop {
    match runtime.run() {
        Ok(event) => match event {
            EVENT_SYSCALL => {
                // Handle syscall
            },
            EVENT_BREAKPOINT => {
                // Handle breakpoint
            },
            CUSTOM_EVENT => {
                // Handle custom events from passes
            },
        },
        Err(fault) => {
            // a fault (e.g. segfault) happened
            break;
        }
    }
}
```
