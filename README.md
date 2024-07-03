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
`squid` is an emulator that is designed to augment traditional _greybox_ fuzzing with advanced crash oracles.
It is best combined with native fuzzers to achieve both, high throughput and enhanced bug finding capabilities.

`squid` offers
- Fast snapshots
- Byte-level permissions on memory
- Ability to rewrite the binaries before emulation
- Integration into LibAFL for the creation of fully-fledged fuzzers
- Decent enough performance due to AOT compilation

However, it can only be used for single-threaded Linux user-space applications that are written in C.
The source of the target _must_ be available because `squid` only supports binaries that have been compiled
with this specific set of flags:
```
-fPIE -pie -O0 -g -fno-jump-tables -mno-relax -D__thread=
```

## Getting started
You can find detailed explanations how to harness `squid` in our [wiki](./wiki).   
For a gentle introduction, see the [hello world](./examples/helloworld) example and for a
full-blown "professional" fuzzer, see our [readelf fuzzer](./examples/readelf).
Finally, consult the documentation on [docs.rs](https://docs.rs/squid).

If you find that something is not properly documented / explained or you have any other questions, please
do not hesitate to [create an issue](https://github.com/fkie-cad/squid/issues/new).
