# Events

- During emulation the guest may throw events to communicate with the host
- there are two standard events: syscalls and breakpoints
- but it is also possible to create and throw custom events
- the syscall and breakpoint event are built into `squid` in order to handle the `ECALL` and `EBREAK`
  RISC-V instructions
- but inside of passes you can also add custom events that carry a custom meaning to your harness
- one example for this is the SQL injection sanitizer in the [README]() that throws an `CHECK_SQL_SYNTAX`
  event that tells the harness to check an SQL query for SQL injection

- custom events can be defined in [Passes]() with the help of the `EventPool`
- each event has a name and a unique ID
- e.g. name of syscall event is `builtin::syscall` and has id 0
- whenever an event is thrown in the guest the event ID gets passed to the harness like so (code example of runtime.run())

- to create a custom event call `EventPool::add_event` with the name of your custom event
- this returns an ID for you to use
- throw the event by synthesizing a `BasicBlock::fire_event` instruction

- you also have the possibility to pass event arguments to the host, similar to function arguments
- this is what the event channel is for
- use the `BasicBlock::push_event_args` instruction to place a number of variables into the event channel right
  before a `BasicBlock::fire_event`
- the harness has access to the event channel via `Runtime::event_channel`
- the harness can also pass some values back to the guest as some kind of "return values" of an event
- `Runtime::event_channel_mut` allows the harness to write back into the event channel and the written
  values can be read by the guest after resuming execution with the `BasicBlock::collect_event_returns` instruction

- (full example)
