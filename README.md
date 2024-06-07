<h1 align="center">
    <a href="">
        <img src="./logo.png" width="128" height="auto">
    </a>
    <br/>
    squid 
    <br/>
</h1>

`squid` is a RISC-V emulator with features that make it a powerful tool for vulnerability research and fuzzing.

Unlike other emulators, `squid` utilizes AOT instead of JIT compilation and allows you to rewrite your target's code before emulation.
During runtime, you get full control over your target by handling all system calls and other events yourself.
This makes it easy to create and combine new sanitizers and test programs for all kinds of vulnerabilities, not just memory corruptions.

Check out [this blog post (todo)]() to get an overview over `squid` and a demonstration of how to apply multiple different sanitizers to a target,
covering SQL injections, command injections, memory corruptions, and information disclosures.

## Features
`squid` is an emulator but its main use case is to augment greybox fuzzing with advanced crash oracles.
It is best combined with a native fuzzer to achieve both, high throughput and enhanced bug finding capabilities.

`squid` offers
- Fast snapshots
- Byte-level permissions on memory
- Ability to rewrite the binaries before emulation
- Integration into LibAFL for the creation of fully-fledged fuzzers
- Decent enough performance due to AOT compilation

However, it can only be used for Linux user-space applications that are written in C.
The source of the target _must_ be available because `squid` only supports binaries that have been compiled
with a specific set of flags.

## Demo
The following snippet of code shows how little effort it takes to create a new sanitizer and apply it to a target with `squid`.   

The sanitizer belows detects SQL injections when `libsqlite3` is being used. It hooks the `sqlite3_exec` function and checks
whether the SQL query has a valid syntax. If that is not the case, it most likely contains fuzz input and we signal a crash.

```rs
use squid::*;
use sqlparser;

// This pass instruments the target
struct SQLiPass;

impl Pass for SQLiPass {
    fn run(
        &mut self,
        image: &mut ProcessImage, 
        event_pool: &mut EventPool, 
        logger: &Logger
    ) -> Result<(), String> {
        // Search libsqlite in the process image
        if let Some(libsqlite) = image.elf_by_filename_mut("libsqlite3.so.0") {
            
            // We are gonna throw this event at the beginning of sqlite3_exec
            let event_check_sql = event_pool.add_event("CHECK_SQL_SYNTAX");
            
            // Search sqlite3_exec function
            for section in libsqlite.iter_sections_mut() {
                for symbol in section.iter_symbols_mut() {
                    if symbol.name("sqlite3_exec").is_some() {
                        
                        // Found the sqlite3_exec function. 
                        // Insert code that throws the CHECK_SQL_SYNTAX
                        // event before executing the function.
                        let chunk = symbol.iter_chunks_mut().first();
                        let ChunkContent::Code(function) = chunk.content_mut() else {
                            unreachable!()
                        };

                        // Synthesize instructions in new BB.
                        // In this case it's only one instruction: FireEvent
                        let mut new_bb = BasicBlock::new();
                        new_bb.fire_event(event_check_sql);

                        // Insert new BB at beginning of CFG
                        let old_entry_id = function.cfg().entry();
                        new_bb.add_edge(Edge::Next(old_entry_id));

                        let new_bb_id = function.cfg_mut().add_basic_block(new_bb);
                        function.cfg_mut().set_entry(new_bb_id);
                    }
                }
            }
        }

        Ok(())
    }
}

fn main() {
    // Prepare the target: load it, instrument it and AOT compile it
    let mut compiler = Compiler::load_elf(
        "path/to/fuzz_target",
        ...
    );
    compiler.run_pass(&mut SQLiPass {});
    let event_check_sql = compiler.event_pool().get_event("CHECK_SQL_SYNTAX");
    let runtime = compiler.compile(...);

    // Then, run it and handle runtime events
    loop {
        match runtime.run() {
            Ok(event) => {
                if event == event_check_sql {
                    // Get query (second argument to function)
                    let a1 = runtime.get_gp_register(GpRegister::a1);
                    let query = runtime.load_string(a1);
                    
                    // Parse query
                    let dialect = sqlparser::dialect::SQLiteDialect {};
                    if sqlparser::parser::Parser::parse_sql(&dialect, query).is_err() {
                        // SQLi !!!
                        break;
                    }
                }
            }
            Err(fault) => {
                break;
            }
        }
    }
}
```

Please note, that for clarity the code leaves out a lot of `unwrap()`s and error handling.

## Getting started
You can find detailed explanations how to harness `squid` in our [wiki](./wiki).   
For a gentle introduction, see the [hello world]() example and for a
full-blown "professional" fuzzer, see our [readelf fuzzer](./examples/readelf).
