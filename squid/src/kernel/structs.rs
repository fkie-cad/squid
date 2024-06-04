#[derive(Debug, Clone)]
#[repr(C)]
pub struct Timespec {
    pub tv_sec: u64,
    pub tv_nsec: u64,
}

#[derive(Debug, Clone)]
#[repr(C)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub unknown: u64,
    pub st_size: u64,
    pub st_blksize: u64,
    pub st_blocks: u64,
    pub st_atime: Timespec,
    pub st_mtime: Timespec,
    pub st_ctime: Timespec,
    pub pad: u64,
}
