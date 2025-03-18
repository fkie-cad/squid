# ewe

`ewe` is a compiler wrapper toolset that extracts metadata from C
code and stores it in addition to the binaries as `.ewe` files.

Its primary purpose is to tackle the information loss problem during compilation
and reconstruct basic block boundaries in machine code.
This enables CFG reconstruction from C code making use of the `goto*` extension.

## Toolchain
The `ewe` tools are part of squid's toolchain and can be found in the `/ewe/` directory
inside the docker container.
The following tools are available:

- `/ewe/gcc`: A wrapper around `riscv64-unknown-linux-gnu-gcc`
- `/ewe/as`: A wrapper around `riscv64-unknown-linux-gnu-as`
- `/ewe/ar`: A wrapper around `riscv64-unknown-linux-gnu-ar`
- `/ewe/ld`: A wrapper around `riscv64-unknown-linux-gnu-ld`

Use these programs instead of their RISC-V counterparts whenever your target uses `goto*` statements.

## Integration into squid
`squid` automatically detects if the binaries it loads have a corresponding `.ewe` file and uses that
for CFG reconstruction.
It is important that the `.ewe` files follow the following convention: For a binary `path/to/binary.ext` that is loaded
by `squid` the `.ewe` file must be named `path/to/binary.ext.ewe`. So, the `.ewe` extension is appended to the filename
in order to signal that this `.ewe` file belongs to this binary.
