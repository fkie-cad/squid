//! The permission bits used by the ClangBackend
#![allow(missing_docs)]

use crate::frontend::Perms;

pub const PERM_NONE: u8 = 0;
/// Indicates that a byte has not been written to. Gets cleared on write.
pub const PERM_UNINIT: u8 = 8;
pub const PERM_READ: u8 = 4;
pub const PERM_WRITE: u8 = 2;
pub const PERM_EXEC: u8 = 1;

/// Used internally by the dynstore_* methods. Signals the start of a heap chunk. DO NOT USE.
pub const PERM_CHUNK_START: u8 = 16;

/// Used internally by the dynstore_* methods. Signals the end of a heap chunk. DO NOT USE.
pub const PERM_CHUNK_END: u8 = 32;

pub(crate) fn convert_loader_perms(perms: Perms) -> u8 {
    let mut new_perms = 0;

    if perms.is_readable() {
        new_perms |= PERM_READ;
    }

    if perms.is_writable() {
        new_perms |= PERM_WRITE;
    }

    if perms.is_executable() {
        new_perms |= PERM_EXEC;
    }

    new_perms
}
