use crate::{
    frontend::VAddr,
    riscv::register::{
        CsrRegister,
        FpRegister,
        GpRegister,
    },
};

pub type SnapshotId = usize;

pub trait Runtime {
    type Error: std::error::Error;
    type Event;

    /* Register I/O */
    fn set_pc(&mut self, pc: VAddr);
    fn get_pc(&self) -> VAddr;
    fn set_gp_register(&mut self, register: GpRegister, value: u64);
    fn get_gp_register(&self, register: GpRegister) -> u64;
    fn set_fp_register(&mut self, register: FpRegister, value: f64);
    fn get_fp_register(&self, register: FpRegister) -> f64;
    fn set_csr_register(&mut self, register: CsrRegister, value: u64);
    fn get_csr_register(&self, register: CsrRegister) -> u64;

    /* Interact with the code */
    fn run(&mut self) -> Result<Self::Event, Self::Error>;

    /* Snapshot handling */
    fn has_snapshot(&self, id: SnapshotId) -> bool;
    fn take_snapshot(&mut self, id: SnapshotId);
    fn restore_snapshot(&mut self, id: SnapshotId) -> Result<(), Self::Error>;
    fn delete_snapshot(&mut self, id: SnapshotId) -> Result<(), Self::Error>;

    /* Event channel I/O */
    fn event_channel(&self) -> &[u64];
    fn event_channel_mut(&mut self, size: usize) -> Result<&mut [u64], Self::Error>;

    /* Memory I/O */
    fn load_dword(&self, address: VAddr) -> Result<u64, Self::Error>;
    fn load_word(&self, address: VAddr) -> Result<u32, Self::Error>;
    fn load_hword(&self, address: VAddr) -> Result<u16, Self::Error>;
    fn load_byte(&self, address: VAddr) -> Result<u8, Self::Error>;
    fn load_slice(&self, address: VAddr, size: usize) -> Result<&[u8], Self::Error>;
    fn store_byte(&mut self, address: VAddr, value: u8) -> Result<(), Self::Error>;
    fn store_hword(&mut self, address: VAddr, value: u16) -> Result<(), Self::Error>;
    fn store_word(&mut self, address: VAddr, value: u32) -> Result<(), Self::Error>;
    fn store_dword(&mut self, address: VAddr, value: u64) -> Result<(), Self::Error>;
    fn store_slice<S: AsRef<[u8]>>(&mut self, address: VAddr, value: S) -> Result<(), Self::Error>;
    fn load_string(&self, address: VAddr) -> Result<&[u8], Self::Error>;
    fn store_string<S: AsRef<str>>(&mut self, address: VAddr, value: S) -> Result<(), Self::Error>;
}
