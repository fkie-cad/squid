# Events

Events are a means of communication between the guest and the host and
can be used to pass information to the harness and back.
They can be thrown at any point in the code with the `FireEvent` IR instruction.
Two events are built into `squid`. The syscall event that is caused by an ECALL instruction
and the breakpoint event that is caused by an EBREAK instruction.
You can also define custom events.

### Creating events
Events can be created inside passes with the `EventPool`.
Call `EventPool::add_event()` with the name of your custom event to get a unique event ID in return.
This event ID can be used in the `FireEvent` instruction to throw your custom event.

### Handling events
An event ID is the return value of the `Runtime::run` method that can be used to execute a target.
The host must inspect that return value and handle it accordingly.

### Event channel
Events have their own arguments and return values such that you can communicate more than just an event ID.
The arguments and return values are placed into the "event channel", which is a buffer of a fixed size.
Push data into the event channel before throwing an event, by using the `PushEventArgs` IR instruction.
Then, when harness handles the event, it can access the arguments via the `Runtime::event_channel()` method.
The harness can in turn place return values into the event channel after handling an event. This is done with
the `Runtime::event_channel_mut()` method. The return values can be collected inside the guest with the `CollectEventReturns`
IR instruction.

## Example
The following example shows how to hook the `malloc()` function of the libc by throwing a custom `HANDLE_MALLOC` event
and using the return value of the event as the return value of the function.

```rs
use squid::*;

struct MallocPass;

impl Pass for MallocPass {
    fn run(&mut self, image: &mut ProcessImage, event_pool: &mut EventPool, logger: &Logger) -> Result<(), ()> {
        // Create a new event in the event pool
        let event_id = event_pool.add_event("HANDLE_MALLOC");

        // Search the malloc function
        let libc = image.elf_by_filename_mut("libc.so.6");
        for section in libc.iter_sections_mut() {
            for symbol in section.iter_symbols_mut() {
                if symbol.name("malloc").is_some() {
                    
                    // Get the CFG of the function
                    let function = symbol.chunk_mut(1).content_mut();
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

