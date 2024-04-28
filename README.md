<h1 align="center">
    <br/>
    <a href="">
        <img src="./logo.png" width="128" height="auto">
    </a>
    <br/>
    squid 
    <br/>
</h1>

`squid` is an emulator with features that make it a powerful tool for vulnerability research and fuzzing.

Unlike other emulators, `squid` utilizes AOT instead of JIT compilation and allows you to write passes that modify the target's code before emulation.
During runtime, you manually handle events like system calls in your harness, giving you total control over your target.
This makes it easy to create new sanitizers and test programs for all kinds of vulnerabilities, not just memory corruption.

Check out [this blog post (todo)]() to take a look under the hood of `squid` and get a demonstration of how to apply four different sanitizers to a target,
covering SQL injections, command injections, memory corruptions, and information disclosures.

## Features
While `squid` was built to enhance traditional greybox fuzzing, it has certain limitations.

`squid` offers
- Fast snapshots
- Byte-level permissions on memory
- Custom instrumentation by custom passes
- Good perf due to AOT compilation
- Integration into LibAFL for the creation of fully-fledged fuzzers

However, it can only be used for Linux user-space applications that are written in C and compiled with a specific set of flags.

## Getting started
The usual workflow of fuzzing with `squid` involves the following steps:

1. Compile your fuzz target with the provided RISC-V toolchain
2. Harness the emulator: Write passes to instrument the target, run the target, create snapshots, etc.
3. Integrate the harness into a fuzzer with LibAFL
4. Optionally, use the fuzzer in a multi-instance fuzzing setup alongside native fuzzers for maximum performance

You can find detailed explanations how to harness `squid` in our [wiki](./wiki).   
For a concrete example that covers all the steps from above, check out our [readelf fuzzer](./examples/readelf).

