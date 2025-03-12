<h1 align="center">
    <a href="">
        <img src="./logo.png" width="128" height="auto">
    </a>
    <br/>
    squid 
    <br/>
</h1>

`squid` is a RISC-V emulator with features that make it a powerful tool for vulnerability research and fuzzing.

It utilizes AOT instead of JIT compilation and allows you to rewrite the binary's code before emulation.
During runtime, you get full control over your target by handling all system calls and other events yourself.
This makes it easy to create and combine new sanitizers and test programs for all kinds of vulnerabilities, not just memory corruptions.

## Features
- Fast snapshots
- Byte-level permissions on memory
- Rewriting binaries before emulation
- Good integration into LibAFL

However, it can only run single-threaded Linux user-space applications that are written in C.  
The source of the target _must_ be available because `squid` only supports binaries that have been compiled
with a specific set of flags.
This makes `squid` unsuitable for blackbox fuzzing. Instead, it was built to augment traditional greybox fuzzing.
It is encouraged to combine `squid` with native fuzzers to achieve both, high throughput and enhanced bug detection.

## Demo
As a quick appetizer let's have a look at how we can overcome common restrictions of native sanitizers with `squid`.

One of the biggest restrictions is that multiple sanitizers cannot be combined in a single build.
Trying to invoke a compiler like this:
```
clang -fsanitize=address,memory
```
results in
```
clang: error: invalid argument '-fsanitize=address' not allowed with '-fsanitize=memory'
```

However, since `squid` allows us to do binary rewriting, we can recreate ASAN + MSAN ourselves.
We just have to compile our target with this specific set of flags:
```
-fPIE -pie -O0 -g -fno-jump-tables -mno-relax -D__thread=
```

And then we can use `squid` to build for emulation with ASAN and MSAN:
```rs
fn main() {
    // 1) Load and lift the target binary into our custom IR
    let mut compiler Compiler::loader()
        .binary("./some-riscv-binary")  // The target binary
        .load();

    // 2) Run the ASAN pass over the binary to insert redzones
    //    and interceptors for the heap functions
    let mut asan_pass = AsanPass::new();
    compiler.run_pass(&mut asan_pass);

    // 3) AOT compile functions in IR down to native machine code by
    //    translating the IR to C code that we can compile with clang
    let backend = ClangBackend::builder()
        .stack_size(2 * 1024 * 1024)
        .heap_size(16 * 1024 * 1024)
        .enable_uninit_stack(true) // MemorySanitizer
        .build();
    let mut runtime = compiler.compile(backend);

    // 4) Emulate the binary, forward syscalls and handle interceptors
    println!("Running...");
    
    loop {
        match runtime.run() {
            Ok(event) => match event {
                EVENT_SYSCALL => /* we have to emulate system calls ourselves here... */,
            },
            Err(fault) => /* Some kind of fault occured (e.g. segfault) */,
        }
    }
}
```

And then, we could go even further and write more custom sanitizers to catch a broader range
of vulnerabilities.

## Getting Started
You can find detailed explanations how to harness `squid` in our [wiki](./wiki).   
For a gentle introduction, see the [hello world](./examples/helloworld) example.   
For an example how to combine native and emulation-based fuzzing for maximum effectiveness, see our [readelf fuzzer](./examples/readelf).  

If you find that something is not properly documented / explained or you have any other questions, please
do not hesitate to [create an issue](https://github.com/fkie-cad/squid/issues/new).
