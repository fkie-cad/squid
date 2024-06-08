# Events

- events are a means of communication between the guest and the host
- events can be thrown with the `FireEvent` IR instruction
- two examples of events are the builtin syscall event and the builtin breakpoint event that stem
  from ECALL / EBREAK instructions
- you can define custom events in passes

### Creating events
- events can be created by the `EventPool` that you can access inside passes
- call `EventPool::add_event` with the name of your event and get a unique event ID in return
- throw events by injecting the `FireEvent` instruction into the target
- `FireEvent` takes an event id as argument

### Event channel
- you can communicate more than just the event id
- events have arguments and return values
- these are placed into the "event channel"
- to push some arguments into the event channel before throwing an event use the `PushEventArgs` instruction
- then when the harness receives an event, it can access the arguments via the `Runtime::event_channel` method
- the harness can place return values into the event channel before resuming execution via the `Runtime::event_channel_mut` method
- These return values can be collected inside the guest via the `CollectEventReturns` instruction

### Example
- example pass that replaces that hooks the `malloc()` function so that the harness can handle the allocation
  instead of the libc

TODO: check that this compiles
```rs
use squid::*;

struct MallocPass;

impl Pass for MallocPass {
    fn run(&mut self, image: &mut ProcessImage, event_pool: &mut EventPool, logger: &Logger) -> Result<(), String> {
        // Create a new event in the event pool
        let event_id = event_pool.add_event("HANDLE_MALLOC");

        // Search the malloc function
        let libc = image.elf_by_filename_mut("libc.so.6");
        for section in libc.iter_sections_mut() {
            for symbol in section.iter_symbols_mut() {
                if symbol.name("malloc").is_some() {
                    
                    // Get the CFG of the function
                    let ChunkContent::Code(function) = symbol.chunk_mut(1).content_mut() else {
                        unreachable!()
                    };
                    let cfg = function.cfg_mut();
                    
                    // This bb pushes the argument onto the event channel and throws the HANDLE_MALLOC event
                    let mut bb1 = BasicBlock::new();
                    let a0 = bb1.load_gp_register(GpRegister::a0);
                    bb1.push_event_args([a0]);
                    bb1.fire_event(event_id);

                    // This bb collects the address from the harness and returns it
                    let mut bb2 = BasicBlock::new();
                    let rets = bb2.collect_event_returns(1);
                    bb2.store_gp_register(GpRegister::a0, rets[0]);
                    let ra = bb2.load_gp_register(GpRegister::ra);
                    bb2.jump(ra);

                    // Replace the malloc function with these two basic blocks
                    cfg.clear();
                    let bb2_id = cfg.add_basic_block(bb2);
                    bb1.add_edge(Edge::Next(bb2_id));
                    let bb1_id = cfg.add_basic_block(bb1);
                    cfg.set_entry(bb1_id);

                    // Now the malloc() function consists entirely of the two basic blocks from above and
                    // the harness has full control over the allocation strategy.
                }
            }
        }

        Ok(())
    }
}
```

