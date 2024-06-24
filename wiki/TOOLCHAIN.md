# Toolchain

`squid` is a RISC-V emulator, so you have to compile every target you want to fuzz to RISC-V.
This can be done in the docker container that comes with `squid` and provides you with a RISC-V gcc toolchain.

You can either build the toolchain from scratch:
```
docker pull rust:latest
docker pull archlinux:latest
docker build -t squid-toolchain --build-arg="jobs=$(nproc)" .
```

Or you can download a pre-built image from docker hub (2.56GB):
```
docker pull pdfkie/squid-toolchain
```

Inside the container, you can find the cross-compiler at `/riscv/bin/riscv64-unknown-linux-gnu-gcc` and the sysroot at
`/riscv/sysroot/`.

Please note that `squid` has certain requirements for the binaries it can emulate.
The binaries __must__ be compiled with the flags
```
-fPIE -pie -O0 -g -fno-jump-tables -mno-relax -D__thread=
```
and must not use thread-local storage, otherwise they won't work with `squid`.

If your target makes use of the C extension that enables `goto*` statements and references to labels,
use `/ewe/gcc` instead of `riscv64-unknown-linux-gnu-gcc`.
This tool is a compiler wrapper that collects certain metadata about the code and is necessary to
correctly reconstruct CFG's. It produces an `.ewe` file alongside your binary that contains said metadata.
For more information on this see the documentation of [ewe](../ewe).

