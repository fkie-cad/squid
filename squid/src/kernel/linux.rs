use std::ops::Range;

use libc;
use rustc_hash::FxHashMap;
use thiserror::Error;

use crate::{
    kernel::{
        fs,
        fs::{
            FileHandle,
            FileSystemError,
            Fs,
        },
        structs::{
            Stat,
            Timespec,
        },
    },
    runtime::SnapshotId,
};

pub type Fd = i32;

#[derive(Error, Debug, Clone)]
pub enum LinuxError {
    #[error("The maximum number of file descriptors has been exhausted")]
    MaxFds,

    #[error("Got an invalid fd: {0}")]
    InvalidFd(usize),

    #[error("Violated the access mode of an opened file")]
    AccessModeViolation,

    #[error("Attempted an operation on a closed fd")]
    ClosedFd,

    #[error("Attempted an invalid operation")]
    InvalidOperation,

    #[error("Supplied invalid argument to syscall")]
    InvalidArgument,

    #[error("Not enough space left on device")]
    NotEnoughSpace,

    #[error("fs error: {0:?}")]
    FsError(#[from] FileSystemError),

    #[error("Attempted invalid operation on the fuzz input")]
    InvalidFuzzInputOperation,
}

#[derive(Clone)]
enum FileType {
    Stdin,
    Stdout,
    Stderr,
    File(FileHandle),
    FuzzInput { size: usize },
    //Dir(DirHandle),
}

#[derive(Clone)]
struct File {
    refcount: usize,
    typ: FileType,
    offset: usize,
    is_read: bool,
    is_write: bool,
}

impl File {
    fn restore_snapshot(&mut self, other: &Self) {
        self.refcount = other.refcount;
        self.typ = other.typ.clone();
        self.offset = other.offset;
        self.is_read = other.is_read;
        self.is_write = other.is_write;
    }
}

struct LinuxSnapshot<const FDS: usize> {
    uid: usize,
    gid: usize,
    fds: [Option<usize>; FDS],
    fd_cursor: usize,
    files: Vec<File>,
}

pub struct Linux<const FDS: usize = 1024> {
    fs: Fs,
    uid: usize,
    gid: usize,
    fds: [Option<usize>; FDS],
    fd_cursor: usize,
    files: Vec<File>,
    last_snapshot: SnapshotId,
    snapshots: FxHashMap<SnapshotId, LinuxSnapshot<FDS>>,
    dirty_bits: Vec<u8>,
    max_file_size: usize,
}

macro_rules! copy_vec {
    ($dst:expr, $src:expr) => {
        $dst.clear();
        $dst.extend_from_slice(&$src);
    };
}

impl<const FDS: usize> Linux<FDS> {
    pub fn take_snapshot(&mut self, id: SnapshotId) {
        let snapshot = LinuxSnapshot {
            uid: self.uid,
            gid: self.gid,
            fds: self.fds,
            fd_cursor: self.fd_cursor,
            files: self.files.clone(),
        };
        self.snapshots.insert(id, snapshot);
        self.fs.take_snapshot(id);
    }

    pub fn delete_snapshot(&mut self, id: SnapshotId) -> bool {
        self.snapshots.remove(&id).is_some() | self.fs.delete_snapshot(id)
    }

    pub fn restore_snapshot(&mut self, id: SnapshotId) -> bool {
        let snapshot = match self.snapshots.get(&id) {
            Some(snapshot) => snapshot,
            None => return false,
        };

        if id == self.last_snapshot {
            self.files.truncate(snapshot.files.len());

            'outer: for (i, byte) in self.dirty_bits.iter().enumerate() {
                for j in 0..8 {
                    if (*byte & (1 << j)) != 0 {
                        let file_idx = i * 8 + j;

                        if file_idx >= self.files.len() {
                            break 'outer;
                        }

                        self.files[file_idx].restore_snapshot(&snapshot.files[file_idx]);
                    }
                }
            }
        } else {
            copy_vec!(self.files, snapshot.files);
            self.last_snapshot = id;
        }

        self.uid = snapshot.uid;
        self.gid = snapshot.gid;
        self.fds.copy_from_slice(&snapshot.fds);
        self.fd_cursor = snapshot.fd_cursor;

        for byte in &mut self.dirty_bits {
            *byte = 0;
        }

        self.fs.restore_snapshot(id)
    }
}

impl<const FDS: usize> Linux<FDS> {
    pub fn new(mut fs: Fs, max_file_size: usize) -> Self {
        fs.clear_dirty_bits();
        let mut linux = Self {
            fs,
            uid: 0,
            gid: 0,
            fds: [None; FDS],
            fd_cursor: 0,
            files: Vec::with_capacity(FDS),
            last_snapshot: 0,
            snapshots: FxHashMap::default(),
            dirty_bits: Vec::new(),
            max_file_size,
        };
        assert_eq!(linux.open_file(FileType::Stdin, 0, true, false).unwrap(), 0);
        assert_eq!(linux.open_file(FileType::Stdout, 0, false, true).unwrap(), 1);
        assert_eq!(linux.open_file(FileType::Stderr, 0, false, true).unwrap(), 2);
        linux
    }

    fn mark_dirty(&mut self, file: usize) {
        let byte_idx = file / 8;
        let bit_idx = file % 8;

        if byte_idx >= self.dirty_bits.len() {
            self.dirty_bits.resize(byte_idx + 1, 0);
        }

        self.dirty_bits[byte_idx] |= 1 << bit_idx;
    }

    #[inline]
    pub fn fs(&self) -> &Fs {
        &self.fs
    }

    #[inline]
    pub fn fs_mut(&mut self) -> &mut Fs {
        &mut self.fs
    }

    fn link_file_to_fd(&mut self, file_idx: usize) -> Result<Fd, LinuxError> {
        let fd = self.fd_cursor;

        if fd >= self.fds.len() {
            return Err(LinuxError::MaxFds);
        }

        self.fds[fd] = Some(file_idx);

        self.files[file_idx].refcount += 1;
        self.fd_cursor += 1;

        Ok(fd as Fd)
    }

    fn open_file(&mut self, typ: FileType, offset: usize, is_read: bool, is_write: bool) -> Result<Fd, LinuxError> {
        let idx = self.files.len();
        self.files.push(File {
            refcount: 0,
            typ,
            offset,
            is_read,
            is_write,
        });
        self.link_file_to_fd(idx)
    }

    fn get_file(&mut self, fd: Fd) -> Result<Option<usize>, LinuxError> {
        let fd = fd as usize;

        if fd >= self.fds.len() {
            return Err(LinuxError::InvalidFd(fd));
        }

        if let Some(idx) = self.fds[fd] {
            let file = &self.files[idx];

            if file.refcount == 0 {
                Ok(None)
            } else {
                self.mark_dirty(idx);
                Ok(Some(idx))
            }
        } else {
            Ok(None)
        }
    }

    pub fn fstatat_fuzz_input(&mut self, size: usize) -> Stat {
        let st_mode = libc::S_IFREG | ((fs::PERM_R as u32) << 6);
        Stat {
            st_dev: 65026,
            st_ino: 1,
            st_mode,
            st_nlink: 0,
            st_uid: self.uid as u32,
            st_gid: self.gid as u32,
            st_rdev: 0,
            st_size: size as u64,
            st_blksize: 512,
            st_blocks: (size / 512) as u64 + (size % 512 != 0) as u64,
            unknown: 0,
            st_atime: Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            st_mtime: Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            st_ctime: Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            pad: 0,
        }
    }

    pub fn fstatat(&mut self, dirfd: Fd, filename: &str, flags: i32) -> Result<Stat, LinuxError> {
        assert_eq!(dirfd, libc::AT_FDCWD);
        assert_eq!(flags & !libc::AT_NO_AUTOMOUNT, 0);

        let handle = self.fs.get_file_handle(filename)?;
        let file = self.fs.file(handle)?;
        let st_size = file.content().len() as u64;
        let st_mode = libc::S_IFREG | ((file.perms() as u32) << 6);

        Ok(Stat {
            st_dev: 65026,
            st_ino: 1,
            st_mode,
            st_nlink: 0,
            st_uid: self.uid as u32,
            st_gid: self.gid as u32,
            st_rdev: 0,
            st_size,
            st_blksize: 512,
            st_blocks: (st_size / 512) + (st_size % 512 != 0) as u64,
            unknown: 0,
            st_atime: Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            st_mtime: Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            st_ctime: Timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            pad: 0,
        })
    }

    pub fn write(&mut self, fd: Fd, data: &[u8]) -> Result<usize, LinuxError> {
        if let Some(file) = self.get_file(fd)? {
            let entry = &mut self.files[file];

            if !entry.is_write {
                return Err(LinuxError::AccessModeViolation);
            }

            match &entry.typ {
                FileType::Stdin | FileType::Stdout | FileType::Stderr => {
                    #[cfg(debug_assertions)]
                    print!("{}", String::from_utf8_lossy(data));

                    Ok(data.len())
                },
                FileType::File(handle) => {
                    let offset = entry.offset;
                    let file = self.fs.file_mut(*handle)?;

                    let new_offset = offset.saturating_add(data.len());

                    if new_offset >= self.max_file_size {
                        return Err(LinuxError::NotEnoughSpace);
                    } else if file.content().len() < new_offset {
                        file.content_mut().resize(new_offset, 0);
                    }

                    file.content_mut()[offset..new_offset].copy_from_slice(data);
                    entry.offset = new_offset;

                    Ok(data.len())
                },
                FileType::FuzzInput {
                    ..
                } => Err(LinuxError::InvalidFuzzInputOperation),
            }
        } else {
            Err(LinuxError::ClosedFd)
        }
    }

    #[inline]
    pub fn open_fuzz_input(&mut self, size: usize) -> Result<Fd, LinuxError> {
        self.open_file(
            FileType::FuzzInput {
                size,
            },
            0,
            true,
            false,
        )
    }

    pub fn openat(&mut self, dirfd: Fd, pathname: &str, flags: i32, mode: i32) -> Result<Fd, LinuxError> {
        assert_eq!(dirfd, libc::AT_FDCWD);
        assert_eq!(flags & (libc::O_TMPFILE | libc::O_DIRECTORY), 0);

        let perms = if (flags & libc::O_WRONLY) != 0 {
            fs::PERM_W
        } else if (flags & libc::O_RDWR) != 0 {
            fs::PERM_R | fs::PERM_W
        } else {
            fs::PERM_R
        };

        let handle = if (flags & libc::O_CREAT) != 0 {
            let (dir, filename) = self.fs.split_filename(pathname)?;
            self.fs.touch(dir, filename, (mode >> 6) as u8 & 0b111)?
        } else {
            self.fs.get_file_handle(pathname)?
        };

        let file = self.fs.file_mut(handle)?;

        if (!file.perms() & perms) != 0 {
            return Err(LinuxError::AccessModeViolation);
        }

        if (flags & libc::O_TRUNC) != 0 && (file.perms() & fs::PERM_W) != 0 {
            file.content_mut().clear();
        }

        let offset = if (flags & libc::O_APPEND) != 0 { file.content().len() } else { 0 };
        let is_read = (perms & fs::PERM_R) != 0;
        let is_write = (perms & fs::PERM_W) != 0;

        self.open_file(FileType::File(handle), offset, is_read, is_write)
    }

    pub fn read_fuzz_input(&mut self, fd: Fd, len: usize) -> Result<Range<usize>, LinuxError> {
        if let Some(file) = self.get_file(fd)? {
            let entry = &mut self.files[file];
            let FileType::FuzzInput {
                size,
            } = &entry.typ
            else {
                unreachable!()
            };
            let offset = entry.offset;

            if offset >= *size {
                return Ok(Range {
                    start: *size,
                    end: *size,
                });
            }

            let delta = std::cmp::min(*size - offset, len);
            entry.offset += delta;
            Ok(Range {
                start: offset,
                end: offset + delta,
            })
        } else {
            Err(LinuxError::ClosedFd)
        }
    }

    pub fn read(&mut self, fd: Fd, len: usize) -> Result<&[u8], LinuxError> {
        if let Some(file) = self.get_file(fd)? {
            let entry = &mut self.files[file];

            if !entry.is_read {
                return Err(LinuxError::AccessModeViolation);
            }

            match &entry.typ {
                FileType::Stdout | FileType::Stderr | FileType::Stdin => Ok(&[]),
                FileType::File(handle) => {
                    let offset = entry.offset;
                    let file = self.fs.file(*handle)?;

                    if offset >= file.content().len() {
                        return Ok(&[]);
                    }

                    let delta = std::cmp::min(file.content().len() - offset, len);
                    entry.offset += delta;

                    let ret = &file.content()[offset..offset + delta];
                    Ok(ret)
                },
                FileType::FuzzInput {
                    ..
                } => Err(LinuxError::InvalidFuzzInputOperation),
            }
        } else {
            Err(LinuxError::ClosedFd)
        }
    }

    pub fn seek(&mut self, fd: Fd, offset: i64, whence: i32) -> Result<usize, LinuxError> {
        if let Some(file) = self.get_file(fd)? {
            let entry = &mut self.files[file];

            match &entry.typ {
                FileType::File(handle) => {
                    match whence {
                        libc::SEEK_SET => {
                            if offset < 0 {
                                return Err(LinuxError::InvalidOperation);
                            }
                            entry.offset = offset as usize;
                        },
                        libc::SEEK_CUR => {
                            entry.offset = entry.offset.wrapping_add(offset as usize);
                        },
                        libc::SEEK_END => {
                            let file = self.fs.file(*handle)?;
                            entry.offset = file.content().len().wrapping_add(offset as usize);
                        },
                        _ => return Err(LinuxError::InvalidArgument),
                    }

                    Ok(entry.offset)
                },
                FileType::FuzzInput {
                    size,
                } => {
                    match whence {
                        libc::SEEK_SET => {
                            if offset < 0 {
                                return Err(LinuxError::InvalidOperation);
                            }
                            entry.offset = offset as usize;
                        },
                        libc::SEEK_CUR => {
                            entry.offset = entry.offset.wrapping_add(offset as usize);
                        },
                        libc::SEEK_END => {
                            entry.offset = size.wrapping_add(offset as usize);
                        },
                        _ => return Err(LinuxError::InvalidArgument),
                    }

                    Ok(entry.offset)
                },
                _ => Err(LinuxError::InvalidOperation),
            }
        } else {
            Err(LinuxError::ClosedFd)
        }
    }

    pub fn close(&mut self, fd: Fd) -> Result<(), LinuxError> {
        if let Some(idx) = self.get_file(fd)? {
            let file = &mut self.files[idx];
            file.refcount -= 1;
            self.fds[fd as usize] = None;
        }

        Ok(())
    }

    pub fn is_fuzz_input(&mut self, fd: Fd) -> bool {
        let fd = fd as usize;

        if fd >= self.fds.len() {
            return false;
        }

        if let Some(idx) = &self.fds[fd] {
            return matches!(&self.files[*idx].typ, FileType::FuzzInput { .. });
        }

        false
    }
}
