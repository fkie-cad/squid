<h1 align="center">
    <a href="">
        <img src="./logo.png" width="128" height="auto">
    </a>
    <br/>
    squid 
    <br/>
</h1>

`squid` is a RISC-V emulator with features that make it a powerful tool for vulnerability research and fuzzing.

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

## Demo
The snippet of code below demonstrates how to setup an SQL-injection sanitizer in less than 100 lines of code / less than 30 minutes. 
We detect SQL injections by hooking the `sqlite3_exec` function of the `libsqlite3.so.0` library and check that the query string
has a valid syntax.    
Note that a sanitizer written like this can be combined with other sanitizers to catch a wide variety of bugs.   
For clarity, the code leaves out a lot of `unwrap()`'s and error handling.

```rs
use squid::*;
use sqlparser;

struct SQLiPass;

impl Pass for SQLiPass {
    fn run(&mut self, image: &mut ProcessImage, event_pool: &mut EventPool, logger: &Logger) -> Result<(), String> {
        // We are gonna throw this event at the beginning of sqlite3_exec
        let event_check_sql = event_pool.add_event("CHECK_SQL_SYNTAX");

        // Search libsqlite in the process image
        let libsqlite = image.elf_by_filename_mut("libsqlite3.so.0");

        // Search sqlite3_exec function
        for section in libsqlite.iter_sections_mut() {
            for symbol in section.iter_symbols_mut() {
                if symbol.name("sqlite3_exec").is_some() {
                    // Found the sqlite3_exec function, insert code that throws the CHECK_SQL_SYNTAX event
                    // before executing the function.
                    let chunk = symbol.iter_chunks_mut().first();
                    let ChunkContent::Code(function) = chunk.content_mut() else { unreachable!() };
                    let old_entry_id = function.cfg().entry();
                    let mut new_bb = BasicBlock::new();

                    // Synthesize instructions in new BB. In this case it's only one instruction.
                    new_bb.fire_event(event_check_sql);

                    // Insert BB at beginning of CFG
                    new_bb.add_edge(Edge::Next(old_entry_id));
                    let new_bb_id = function.cfg_mut().add_basic_block(new_bb);
                    function.cfg_mut().set_entry(new_bb_id);
                }
            }
        }

        Ok(())
    }
}

fn main() {
    /* Prepare the target: load it, instrument it and AOT compile it */
    let mut compiler = Compiler::load_elf(
        "path/to/fuzz_target",
        ...
    );
    compiler.run_pass(&mut SQLiPass {});
    let event_check_sql = compiler.event_pool().get_event("CHECK_SQL_SYNTAX");
    let runtime = compiler.compile(...);

    /* Then, run it and handle runtime events */
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

## Getting started
You can find detailed explanations how to harness `squid` in our [wiki](./wiki).   
For a concrete example, see our [readelf fuzzer](./examples/readelf).

