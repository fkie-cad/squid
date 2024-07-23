<h1 align="center">
    <a href="">
        <img src="./logo.png" width="128" height="auto">
    </a>
    <br/>
    squid 
    <br/>
</h1>

`squid` is a RISC-V emulator with features that make it a powerful tool for vulnerability research and fuzzing.

Unlike other emulators, `squid` utilizes AOT instead of JIT compilation and allows you to rewrite the binary's code before emulation.
During runtime, you get full control over your target by handling all system calls and other events yourself.
This makes it easy to create and combine new sanitizers and test programs for all kinds of vulnerabilities, not just memory corruptions.

Check out [this blog post (todo)]() to get an overview over `squid` and a demonstration of how to apply multiple different sanitizers to a target,
covering SQL injections, command injections, memory corruptions, and information disclosures.

## Features
`squid` offers

- Fast snapshots
- Byte-level permissions on memory
- Rewriting binaries before emulation
- Integration into LibAFL
- Decent enough performance due to AOT compilation

However, it can only run single-threaded Linux user-space applications that are written in C.  
The source of the target _must_ be available because `squid` only supports binaries that have been compiled
with a specific set of flags.
This makes `squid` unsuitable for blackbox fuzzing. Instead, it was built to augment greybox fuzzing with advanced crash oracles.
It is encouraged to combine `squid` with native fuzzers to achieve both, high throughput and enhanced bug detection.

## Demo
Below you can see a demo program that demonstrates how to overcome common restrictions of native sanitizers with `squid`.
One of the biggest restrictions is that multiple sanitizers cannot be combined in a single build.
Trying something like
```
clang -fsanitize=address,memory,undefined test.c
```
results in
```
clang: error: invalid argument '-fsanitize=address' not allowed with '-fsanitize=memory'
```

Since `squid` allows us to rewrite the binary before emulation we can simply recreate ASAN + MSAN instrumentation
ourselves:
```rs
use squid::*;

fn main() {
    // 1) Load the binary and lift it into our custom IR
    let mut compiler = Compiler::load_elf(
        "helloworld", // The target binary
        &["."], // LD_LIBRARY_PATH
        &[]
    ).unwrap();

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
        .source_file("/tmp/demo.c") // The AOT code goes into this file
        .build()
        .unwrap();
    let mut runtime = compiler.compile(backend).unwrap();

    // 4) Emulate the binary, forward syscalls and handle interceptors
    loop {
        match runtime.run() {
            Ok(event) => match event {
                EVENT_BREAKPOINT => panic!("Hit a breakpoint"),
                EVENT_SYSCALL => forward_syscall(&mut runtime).unwrap(),
                _ => asan_pass.handle_event(event, &mut runtime).unwrap(),
            },
            Err(fault) => panic!("Found a crash: {:?}", fault),
        }
    }
}
```

Let's create an example program that has either an out-of-bounds or an uninitialized access:

And when we run it we get:

(asciinema)

## Getting started
You can find detailed explanations how to harness `squid` in our [wiki](./wiki).   
For a gentle introduction, see the [hello world](./examples/helloworld) example and for a
full-blown "professional" fuzzer, see our [readelf fuzzer](./examples/readelf).
Finally, consult the documentation on [docs.rs](https://docs.rs/squid).

If you find that something is not properly documented / explained or you have any other questions, please
do not hesitate to [create an issue](https://github.com/fkie-cad/squid/issues/new).
