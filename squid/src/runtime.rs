//! Contains the [`Runtime`] trait.

use crate::{
    frontend::VAddr,
    riscv::register::{
        CsrRegister,
        FpRegister,
        GpRegister,
    },
};

/// Snapshots are referred to by IDs of this type
pub type SnapshotId = usize;

/// This trait contains the minimum behavior that is expected from any runtime.
pub trait Runtime {
    /// Each runtime has its corresponding error type
    type Error: std::error::Error;

    /// The Event is the return value of the [`Runtime::run`] function
    type Event;

    /* Register I/O */
    /// Set the program counter to the specified address
    fn set_pc(&mut self, pc: VAddr);
    /// Get the program counter of the program
    fn get_pc(&self) -> VAddr;
    /// Store a value into a general puporse register
    fn set_gp_register(&mut self, register: GpRegister, value: u64);
    /// Retrieve the value of a general purpose register
    fn get_gp_register(&self, register: GpRegister) -> u64;
    /// Store a value into a floating point register
    fn set_fp_register(&mut self, register: FpRegister, value: f64);
    /// Retrieve the value of a floating point register
    fn get_fp_register(&self, register: FpRegister) -> f64;
    /// Store a value into one of the control/status registers
    fn set_csr_register(&mut self, register: CsrRegister, value: u64);
    /// Retrieve the value of one of the control/status registers
    fn get_csr_register(&self, register: CsrRegister) -> u64;

    /* Interact with the code */
    /// Execute the program starting at the current program counter until an event is thrown
    fn run(&mut self) -> Result<Self::Event, Self::Error>;

    /* Snapshot handling */
    /// Check if a snapshot with the given ID is available
    fn has_snapshot(&self, id: SnapshotId) -> bool;
    /// Take a snapshot of the current program state and assign it the given ID.
    /// If a snapshot with the same ID has already been created, it is overwritten.
    fn take_snapshot(&mut self, id: SnapshotId);
    /// Given a snapshot ID, restore the corresponding snapshot
    fn restore_snapshot(&mut self, id: SnapshotId) -> Result<(), Self::Error>;
    /// Delete the snapshot with the given ID from the snapshot store
    fn delete_snapshot(&mut self, id: SnapshotId) -> Result<(), Self::Error>;

    /* Event channel I/O */
    /// Get read-only access to the data in the event channel
    fn event_channel(&self) -> &[u64];
    /// Get write-access to the event channel. `size` determines how many elements you want to place into the event channel.
    fn event_channel_mut(&mut self, size: usize) -> Result<&mut [u64], Self::Error>;

    /* Memory I/O */
    /// Return the memory contents at the given address as a dword (8 bytes)
    fn load_dword(&self, address: VAddr) -> Result<u64, Self::Error>;
    /// Return the memory contents at the given address as a word (4 bytes)
    fn load_word(&self, address: VAddr) -> Result<u32, Self::Error>;
    /// Return the memory contents at the given address as an hword (2 bytes)
    fn load_hword(&self, address: VAddr) -> Result<u16, Self::Error>;
    /// Return the memory contents at the given address as a byte
    fn load_byte(&self, address: VAddr) -> Result<u8, Self::Error>;
    /// Return the memory contents at the given address as an array of bytes with size `size`
    fn load_slice(&self, address: VAddr, size: usize) -> Result<&[u8], Self::Error>;
    /// Store the given value at the given address as a byte
    fn store_byte(&mut self, address: VAddr, value: u8) -> Result<(), Self::Error>;
    /// Store the given value at the given address as a hword (2 bytes)
    fn store_hword(&mut self, address: VAddr, value: u16) -> Result<(), Self::Error>;
    /// Store the given value at the given address as a word (4 bytes)
    fn store_word(&mut self, address: VAddr, value: u32) -> Result<(), Self::Error>;
    /// Store the given value at the given address as a dword (8 bytes)
    fn store_dword(&mut self, address: VAddr, value: u64) -> Result<(), Self::Error>;
    /// Store the given byte array at the given address
    fn store_slice<S: AsRef<[u8]>>(&mut self, address: VAddr, value: S) -> Result<(), Self::Error>;
    /// Retreive a NUL-terminated string at the given address.
    /// The NUL terminator must not be included in the return value but exists in memory.
    fn load_string(&self, address: VAddr) -> Result<&[u8], Self::Error>;
    /// Store the provided string as is at the given address. A NUL-terminator must be added by the implementation.
    fn store_string<S: AsRef<str>>(&mut self, address: VAddr, value: S) -> Result<(), Self::Error>;
}
