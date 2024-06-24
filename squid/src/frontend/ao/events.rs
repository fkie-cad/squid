//! Contains all the events that can be thrown by RISC-V instructions

/// The syscall event is thrown by the ECALL instruction
pub const EVENT_SYSCALL: &str = "builtin::syscall";

/// The breakpoint event is thrown by the EBREAK instruction
pub const EVENT_BREAKPOINT: &str = "builtin::breakpoint";
