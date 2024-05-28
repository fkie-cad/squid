# Process Image

The process image is a data structure that contains the code and data of ELF files.   
Its primary purpose is to make manipulation of code and data easy and accessible.   
The ELF files that appear in a process image are an executable - e.g. our fuzz target - and all its depedencies.
Think of it as an ELF loader except that the result is a hierachical tree structure instead of a
linear memory image. This hierachical approach makes it is easy to modify 
and/or rearrange the contents of ELF files.

Creating a process image is the first step in using `squid` and can be done with `Compiler::load_elf`:
```rs
let mut compiler = Compiler::load_elf(
    // The executable that we want to load
    "/path/to/binary",
    
    // Directories that contain the dependencies of the executable similar to LD_LIBRARY_PATH
    &[
        "/path/with/deps",
    ],
    
    // List of shared objects to preload similar to LD_PRELOAD
    &[
        "/path/to/library.so",
    ]
).expect("Loading binary failed");
```

This produces a process image that looks something like this:
![](./symimg.png)
This image is an excerpt. The full graph can be found [here](./symimg.svg).

As you can see the process image is a tree.   
The root points to all loaded ELF files. In this case these are a "helloworld" executable and its dependency "libc.so.6".
The children of the ELF files are their allocatable sections (here identified by their
permission bits "rwx").
The children of the sections are all ELF symbols that are inside these sections. For example the symbol
"main" is a child of the section "r-x" because the program has a `main()` function.
The leafs of the process image are so-called "chunks". Chunks hold the actual contents of a symbol and
tell us how to interpret the stream of bytes. It can either be code, data or a pointer.

One of the main things you're gonna do with a process image is traverse it.
This can be done like so:
```rs
for elf in compiler.process_image().iter_elfs() {
    for section in elf.iter_sections() {
        for symbol in section.iter_symbols() {
            for chunk in symbol.iter_chunks() {
                match chunk.content() {
                    ChunkContent::Code(code) => {
                        // ...
                    },
                    ChunkContent::Data { bytes, perms } => {
                        // ...
                    },
                    ChunkContent::Pointer(pointer) => {
                        // ...
                    },
                }
            }
        }
    }
}
```

You can also add new nodes, delete nodes or modify existing nodes.   
To add new nodes call their respective builder objects, e.g. `Elf::builder()` or
`Section::builder()` and insert the newly created nodes via the `insert_*`
methods like `elf.insert_section(...)` or `section.insert_symbol(...)`.

## Symbolization
One key thing that we have left out so far is how `squid` handles the code in ELF files.   
Since the point of the process image is to manipulate binaries, we run into one particular problem.
Whenever there are pointers to objects inside an ELF file, these pointers become invalid as soon as
the ELF file gets rearranged.   
The way `squid` handles this problem is that it abstracts pointers with concrete values away to higher-level
"symbolic pointers".
A symbolic pointer is also a pointer but it points to a chunk in the process image instead of a concrete memory location.
You may have noticed that in the image above each node in the tree is prefixed with a number in square brackets.
This is the ID of the element. Each child of each node gets a unique ID such that we can identify chunks with a
5-tuple of IDs: `(elf_id, section_id, symbol_id, chunk_id)`.
For example, every concrete pointer to the `main()` function has the value `0x4c0` in the ELF file but gets replaced with `(1, 2, 5, 1)`
in the process image.

In order to do this symbolization technique, the RISC-V code has to be lifted into an IR that is specifically designed
to make such symbolizations easy. This also means that when you want to manipulate the code of a function, you have to
do it on the higher-level IR instead of the raw RISC-V code.

You also might want to have a look at [RetroWrite](https://github.com/HexHive/RetroWrite), a tool that employs a similar symbolization technique but in the context of blackbox fuzzing.

