# Overview over squid

This page briefly gives you an overview over the most important aspects of `squid`.
Usage of `squid` can be divided into 3 phases:

1. Compile the target to RISC-V
2. Load the binary with the emulator
    1. Create a process image that contains the target and all its dependencies
    2. Run passes that modify functions and data
    3. Compile the code in the binary to your native ISA
3. Run the target

Each of these steps is explained in more detail below.

## Compiling the target
Please follow the instructions in [TOOLCHAIN.md](./TOOLCHAIN.md) when compiling your target
to RISC-V.

## Loading the binary
Once you have compiled the binary and all it's dependencies, the next step is to
load the binary and create a process image:
```rs
use squid::Compiler;

let mut compiler = Compiler::load_elf(
    /* The binary that we want to emulate */
    "/path/to/binary",
    
    /* Directories that contain the dependencies of the binary similar to LD_LIBRARY_PATH */
    &[
        "/path/with/deps",
    ],
    
    /* List of shared objects to preload. Similar to LD_PRELOAD */
    &[
        "/path/to/library.so",
    ]
).expect("Loading binary failed");
```

This creates a "symbolic process image" that is the basis for all further operations.
All RISC-V instructions are lifted into a custom IR and all pointers are replaced with "symbolic references".
A "symbolic reference" is like a pointer except that it does not contain a virtual address but a tuple 
`(Elf, Section, Symbol, Offset)` that represents offsets into symbols of loaded ELF files.
With such "symbolized" binaries we can now go ahead and modify their code and data without worrying about adjusting
offsets or references.

## Running Passes
Once we have lifted all functions in the binary to our custom IR, we can run passes to modify the functions.
A pass in `squid` is a simple struct that implements the trait `Pass` like this:
```rs
use squid::{
    passes::Pass,
    frontend::ProcessImage,
    event::EventPool,
    Logger,
};

struct MyPass;

impl Pass for MyPass {
    fn name(&self) -> String {
        // return the name of this pass here
    }

    fn run(&mut self, image: &mut ProcessImage, event_pool: &mut EventPool, logger: &Logger) -> Result<(), String> {
        // modify process image here
    }
}

/* Run the pass with the compiler */
compiler.run_pass(&mut MyPass {}).expect("Pass had an error");
```

## Creating a Runtime
To emulate the code in a process image we create a runtime with the help of a backend.
A backend takes the symbolic process image, compiles the functions from IR to native code
and provides a runtime that can execute this code.

Currently, `squid` comes with the `MultiverseBackend`.
Use it like so:
```rs
use squid::backends::multiverse::MultiverseBackend;

/* Create the backend responsible for compilation */
let backend = MultiverseBackend::builder()
    .heap_size(4 * 1024 * 1024)   // Size of the heap region
    .stack_size(2 * 1024 * 1024)  // Size of the stack region
    .source_file("generated_code.c") // See the docs for what this means...
    .build()
    .expect("Could not configure backend");

/* Run the backend with the compiler */
let runtime = compiler.compile(backend).expect("Backend had an error");
```

## Running the target
To execute our target, we call the `Runtime::run` method. This will trigger certain events like
system calls or breakpoints that we must handle. Passes can also define custom events

```rs
loop {
    match runtime.run() {
        Ok(event) => {
            // handle event and continue execution
        },
        Err(fault) => {
            // handle fault, e.g. signal a crash to the fuzzer

            break;
        }
    }
}
```


