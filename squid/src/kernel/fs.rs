use std::{
    collections::HashMap,
    convert::Into,
    ffi::{
        OsStr,
        OsString,
    },
    path::{
        Component,
        Path,
    },
};

use rustc_hash::FxHashMap;
use thiserror::Error;

use crate::runtime::SnapshotId;

pub const PERM_NONE: u8 = 0;
pub const PERM_R: u8 = 4;
pub const PERM_W: u8 = 2;
pub const PERM_X: u8 = 1;

#[derive(Error, Debug, Clone)]
pub enum FileSystemError {
    #[error("Not found")]
    NotFound,

    #[error("Not a directory")]
    NotADirectory,

    #[error("Duplicate name")]
    DuplicateName,

    #[error("Invalid name")]
    InvalidName,

    #[error("Not a file")]
    NotAFile,

    #[error("Invalid handle")]
    InvalidHandle,

    #[error("Invalid permissions")]
    InvalidPermissions,

    #[error("Could not chdir")]
    ChDirError,

    #[error("Could not create link")]
    InvalidLinkTarget,
}

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
struct TreeIndex(usize);

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
struct FileIndex(usize);

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
struct DirIndex(usize);

#[derive(Clone, Debug)]
pub struct File {
    parent: TreeIndex,
    deleted: bool,
    locked: bool,
    content: Vec<u8>,
    perms: u8,
}

impl File {
    fn new(parent: TreeIndex, perms: u8) -> Self {
        Self {
            parent,
            deleted: false,
            locked: false,
            content: Vec::new(),
            perms,
        }
    }

    fn restore_snapshot(&mut self, other: &Self) {
        self.parent = other.parent;
        self.deleted = other.deleted;
        self.locked = other.locked;
        self.perms = other.perms;
        self.content.resize(other.content.len(), 0);
        self.content[..].copy_from_slice(&other.content);
    }

    pub fn perms(&self) -> u8 {
        self.perms
    }

    pub fn set_perms(&mut self, perms: u8) {
        self.perms = perms;
    }

    pub fn lock(&mut self) {
        self.locked = true;
    }

    pub fn unlock(&mut self) {
        self.locked = false;
    }

    pub fn locked(&self) -> bool {
        self.locked
    }

    pub fn content(&self) -> &[u8] {
        &self.content
    }

    pub fn content_mut(&mut self) -> &mut Vec<u8> {
        &mut self.content
    }
}

#[derive(Clone, Debug)]
pub struct Directory {
    deleted: bool,
    locked: bool,
    perms: u8,
    parent: TreeIndex,
    children: HashMap<OsString, TreeIndex>,
}

impl Directory {
    fn new(parent: TreeIndex, perms: u8) -> Self {
        Self {
            deleted: false,
            locked: false,
            perms,
            parent,
            children: HashMap::default(),
        }
    }

    fn restore_snapshot(&mut self, other: &Self) {
        self.deleted = other.deleted;
        self.locked = other.locked;
        self.perms = other.perms;
        self.parent = other.parent;

        for (key, value) in &other.children {
            if !self.children.contains_key(key) {
                self.children.insert(key.clone(), *value);
            }
        }

        self.children.retain(|key, _| other.children.contains_key(key));
    }

    pub fn perms(&self) -> u8 {
        self.perms
    }

    pub fn set_perms(&mut self, perms: u8) {
        self.perms = perms;
    }

    pub fn lock(&mut self) {
        self.locked = true;
    }

    pub fn unlock(&mut self) {
        self.locked = false;
    }

    pub fn locked(&self) -> bool {
        self.locked
    }
}

#[derive(Clone, Debug)]
enum Node {
    Link(TreeIndex),
    File(FileIndex),
    Directory(DirIndex),
}

impl Node {
    #[inline]
    fn is_dir(&self) -> bool {
        matches!(self, Node::Directory { .. })
    }

    #[inline]
    fn is_file(&self) -> bool {
        matches!(self, Node::File(_))
    }
}

#[derive(Copy, Clone, Debug)]
pub struct DirHandle(TreeIndex);

impl From<DirHandle> for TreeIndex {
    fn from(val: DirHandle) -> Self {
        val.0
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(transparent)]
pub struct FileHandle(TreeIndex);

impl From<FileHandle> for TreeIndex {
    fn from(val: FileHandle) -> Self {
        val.0
    }
}

struct FsSnapshot {
    files: Vec<File>,
    dirs: Vec<Directory>,
    tree: Vec<Node>,
    root: TreeIndex,
    cwd: TreeIndex,
    umask: u8,
}

pub struct Fs {
    files: Vec<File>,
    dirs: Vec<Directory>,
    tree: Vec<Node>,
    root: TreeIndex,
    cwd: TreeIndex,
    umask: u8,
    last_snapshot: SnapshotId,
    snapshots: FxHashMap<SnapshotId, FsSnapshot>,
    dirty_bits: Vec<u8>,
}

impl Fs {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let dir = Directory::new(TreeIndex(0), PERM_R | PERM_W | PERM_X);

        Self {
            files: Vec::new(),
            dirs: vec![dir],
            tree: vec![Node::Directory(DirIndex(0))],
            root: TreeIndex(0),
            cwd: TreeIndex(0),
            umask: 0,
            last_snapshot: SnapshotId::default(),
            snapshots: FxHashMap::default(),
            dirty_bits: Vec::new(),
        }
    }

    #[inline]
    pub(crate) fn clear_dirty_bits(&mut self) {
        for byte in &mut self.dirty_bits {
            *byte = 0;
        }
    }

    fn mark_node_dirty(&mut self, node: usize) {
        let byte_idx = node / 8;
        let bit_idx = node % 8;

        if byte_idx >= self.dirty_bits.len() {
            self.dirty_bits.resize(byte_idx + 1, 0);
        }

        self.dirty_bits[byte_idx] |= 1 << bit_idx;
    }

    fn check_handle<H: Into<TreeIndex>>(&self, handle: H) -> Result<(), FileSystemError> {
        if handle.into().0 < self.tree.len() {
            Ok(())
        } else {
            Err(FileSystemError::InvalidHandle)
        }
    }

    fn follow_links(&self, mut idx: TreeIndex) -> TreeIndex {
        while let Node::Link(new_idx) = &self.tree[idx.0] {
            idx = *new_idx;
        }

        idx
    }

    fn is_deleted(&self, node: TreeIndex) -> bool {
        match &self.tree[node.0] {
            Node::Link(tree_idx) => self.is_deleted(self.follow_links(*tree_idx)),
            Node::File(file_idx) => self.files[file_idx.0].deleted,
            Node::Directory(dir_idx) => self.dirs[dir_idx.0].deleted,
        }
    }

    fn find_tree_index(&self, path: &Path) -> Option<TreeIndex> {
        let mut cursor = self.cwd;

        for comp in path.components() {
            cursor = self.follow_links(cursor);

            if self.is_deleted(cursor) {
                return None;
            }

            let node = self.tree.get(cursor.0)?;

            /* Move to next node */
            match comp {
                Component::Prefix(_) => return None,
                Component::RootDir => cursor = self.root,
                Component::CurDir => {},
                Component::ParentDir => match node {
                    Node::Directory(dir_idx) => {
                        cursor = self.dirs[dir_idx.0].parent;
                    },
                    _ => return None,
                },
                Component::Normal(name) => match node {
                    Node::Directory(dir_idx) => {
                        let dir = self.dirs.get(dir_idx.0)?;

                        if (dir.perms() & PERM_R) == 0 {
                            return None;
                        }

                        cursor = *dir.children.get(name)?;
                    },
                    _ => return None,
                },
            }
        }

        /* Final check */
        cursor = self.follow_links(cursor);

        if self.is_deleted(cursor) {
            return None;
        }

        Some(cursor)
    }

    pub fn umask(&mut self, umask: u8) {
        self.umask = umask;
    }

    pub fn get_directory_handle<P: AsRef<Path>>(&self, path: P) -> Result<DirHandle, FileSystemError> {
        let path = path.as_ref();
        let idx = self.find_tree_index(path).ok_or(FileSystemError::NotFound)?;

        if !self.tree[idx.0].is_dir() {
            Err(FileSystemError::NotADirectory)
        } else {
            Ok(DirHandle(idx))
        }
    }

    pub fn get_file_handle<P: AsRef<Path>>(&self, path: P) -> Result<FileHandle, FileSystemError> {
        let path = path.as_ref();
        let idx = self.find_tree_index(path).ok_or(FileSystemError::NotFound)?;

        if !self.tree[idx.0].is_file() {
            Err(FileSystemError::NotAFile)
        } else {
            Ok(FileHandle(idx))
        }
    }

    pub fn split_filename<'a, P: AsRef<Path> + 'a>(&self, path: P) -> Result<(DirHandle, String), FileSystemError> {
        let path = path.as_ref();

        let parent = path.parent().ok_or(FileSystemError::InvalidName)?;
        let filename = path.file_name().ok_or(FileSystemError::InvalidName)?;

        let handle = if parent.as_os_str().is_empty() { self.cwd() } else { self.get_directory_handle(parent)? };

        let filename = filename.to_string_lossy().into_owned();

        Ok((handle, filename))
    }

    pub fn mkdir<S: Into<OsString> + AsRef<OsStr>>(
        &mut self,
        parent: DirHandle,
        name: S,
        perms: u8,
    ) -> Result<DirHandle, FileSystemError> {
        self.check_handle(parent)?;

        if name.as_ref().is_empty() {
            return Err(FileSystemError::InvalidName);
        }

        let tree_len = self.tree.len();
        let dirs_len = self.dirs.len();

        /* Verify parent directory */
        let Node::Directory(parent_idx) = self.tree[parent.0 .0] else { unreachable!() };
        let dir = &self.dirs[parent_idx.0];

        if dir.deleted {
            return Err(FileSystemError::NotFound);
        } else if (dir.perms() & PERM_W) == 0 {
            return Err(FileSystemError::InvalidPermissions);
        }

        /* Verify child directory */
        if let Some(child_idx) = dir.children.get(name.as_ref()) {
            if !self.is_deleted(*child_idx) {
                return Err(FileSystemError::DuplicateName);
            }
        }

        /* Create new directory */
        self.dirs[parent_idx.0].children.insert(name.into(), TreeIndex(tree_len));
        self.tree.push(Node::Directory(DirIndex(dirs_len)));
        self.dirs.push(Directory::new(parent.0, perms & !self.umask));

        self.mark_node_dirty(parent.0 .0);

        Ok(DirHandle(TreeIndex(tree_len)))
    }

    pub fn touch<S: Into<OsString> + AsRef<OsStr>>(
        &mut self,
        parent: DirHandle,
        name: S,
        perms: u8,
    ) -> Result<FileHandle, FileSystemError> {
        self.check_handle(parent)?;

        if name.as_ref().is_empty() {
            return Err(FileSystemError::InvalidName);
        }

        let tree_len = self.tree.len();
        let files_len = self.files.len();

        /* Verify parent directory */
        let Node::Directory(dir_idx) = self.tree[parent.0 .0] else { unreachable!() };
        let dir = &self.dirs[dir_idx.0];

        if dir.deleted {
            return Err(FileSystemError::NotFound);
        } else if (dir.perms() & PERM_W) == 0 {
            return Err(FileSystemError::InvalidPermissions);
        }

        /* Verify child node */
        if let Some(child_idx) = dir.children.get(name.as_ref()) {
            if !self.is_deleted(*child_idx) {
                return Ok(FileHandle(*child_idx));
            }
        }

        /* Create new file */
        self.files.push(File::new(parent.0, perms & !self.umask));
        self.dirs[dir_idx.0].children.insert(name.into(), TreeIndex(tree_len));
        self.tree.push(Node::File(FileIndex(files_len)));

        self.mark_node_dirty(parent.0 .0);

        Ok(FileHandle(TreeIndex(tree_len)))
    }

    pub fn file(&self, handle: FileHandle) -> Result<&File, FileSystemError> {
        self.check_handle(handle)?;

        match &self.tree[handle.0 .0] {
            Node::File(idx) => {
                let file = &self.files[idx.0];

                if file.deleted {
                    return Err(FileSystemError::NotFound);
                }

                Ok(file)
            },
            _ => Err(FileSystemError::NotAFile),
        }
    }

    pub fn file_mut(&mut self, handle: FileHandle) -> Result<&mut File, FileSystemError> {
        self.check_handle(handle)?;

        self.mark_node_dirty(handle.0 .0);

        match &self.tree[handle.0 .0] {
            Node::File(idx) => {
                let file = &mut self.files[idx.0];

                if file.deleted {
                    return Err(FileSystemError::NotFound);
                }

                Ok(file)
            },
            _ => Err(FileSystemError::NotAFile),
        }
    }

    pub fn directory(&self, handle: DirHandle) -> Result<&Directory, FileSystemError> {
        self.check_handle(handle)?;

        match &self.tree[handle.0 .0] {
            Node::Directory(dir_idx) => {
                let dir = &self.dirs[dir_idx.0];

                if dir.deleted {
                    return Err(FileSystemError::NotFound);
                }

                Ok(dir)
            },
            _ => Err(FileSystemError::NotADirectory),
        }
    }

    pub fn directory_mut(&mut self, handle: DirHandle) -> Result<&mut Directory, FileSystemError> {
        self.check_handle(handle)?;

        self.mark_node_dirty(handle.0 .0);

        match &self.tree[handle.0 .0] {
            Node::Directory(dir_idx) => {
                let dir = &mut self.dirs[dir_idx.0];

                if dir.deleted {
                    return Err(FileSystemError::NotFound);
                }

                Ok(dir)
            },
            _ => Err(FileSystemError::NotADirectory),
        }
    }

    fn delete(&mut self, node: TreeIndex) -> Result<(), FileSystemError> {
        self.mark_node_dirty(node.0);

        match &self.tree[node.0] {
            Node::File(idx) => {
                self.files[idx.0].deleted = true;
                Ok(())
            },
            Node::Link(tree_idx) => self.delete(*tree_idx),
            _ => Err(FileSystemError::NotAFile),
        }
    }

    pub fn rm(&mut self, handle: FileHandle) -> Result<(), FileSystemError> {
        self.check_handle(handle)?;
        self.delete(handle.0)
    }

    fn delete_subtree(&mut self, node: TreeIndex) {
        self.mark_node_dirty(node.0);

        match &self.tree[node.0] {
            Node::Directory(dir_idx) => {
                let dir = &mut self.dirs[dir_idx.0];
                dir.deleted = true;

                let children: Vec<TreeIndex> = dir.children.values().copied().collect();

                for node in children {
                    self.delete_subtree(node);
                }
            },
            Node::File(file_idx) => {
                self.files[file_idx.0].deleted = true;
            },
            Node::Link(tree_idx) => {
                self.delete_subtree(*tree_idx);
            },
        }
    }

    pub fn rmdir(&mut self, handle: DirHandle) -> Result<(), FileSystemError> {
        self.check_handle(handle)?;
        self.delete_subtree(handle.0);
        Ok(())
    }

    pub fn rmlink<S: AsRef<OsStr>>(&mut self, dir: DirHandle, link_name: S) -> Result<(), FileSystemError> {
        self.check_handle(dir)?;

        self.mark_node_dirty(dir.0 .0);

        /* Verify parent directory */
        let Node::Directory(parent_idx) = self.tree[dir.0 .0] else { unreachable!() };
        let dir = &mut self.dirs[parent_idx.0];

        if (dir.perms() & PERM_W) == 0 {
            return Err(FileSystemError::InvalidPermissions);
        }

        /* Remove link */
        if dir.children.remove(link_name.as_ref()).is_none() {
            return Err(FileSystemError::NotFound);
        }

        Ok(())
    }

    pub fn chroot(&mut self, handle: DirHandle) -> Result<(), FileSystemError> {
        self.check_handle(handle)?;

        self.mark_node_dirty(handle.0 .0);

        match &mut self.tree[handle.0 .0] {
            Node::Directory(dir_idx) => {
                let dir = &mut self.dirs[dir_idx.0];

                if dir.deleted {
                    return Err(FileSystemError::NotFound);
                }

                dir.parent = handle.0;
            },
            _ => return Err(FileSystemError::NotADirectory),
        }

        self.root = handle.0;
        Ok(())
    }

    pub fn chdir(&mut self, handle: DirHandle) -> Result<(), FileSystemError> {
        self.check_handle(handle)?;

        self.mark_node_dirty(handle.0 .0);

        match &self.tree[handle.0 .0] {
            Node::Directory(dir_idx) => {
                let dir = &self.dirs[dir_idx.0];

                if dir.deleted {
                    return Err(FileSystemError::NotFound);
                } else if (dir.perms() & PERM_X) == 0 {
                    return Err(FileSystemError::ChDirError);
                }
            },
            _ => return Err(FileSystemError::NotADirectory),
        }

        self.cwd = handle.0;
        Ok(())
    }

    fn link_node<S: Into<OsString> + AsRef<OsStr>>(
        &mut self,
        parent: DirHandle,
        name: S,
        target: TreeIndex,
    ) -> Result<(), FileSystemError> {
        self.check_handle(parent)?;

        if name.as_ref().is_empty() {
            return Err(FileSystemError::InvalidName);
        }

        let tree_len = self.tree.len();

        /* Verify target */
        if self.is_deleted(target) {
            return Err(FileSystemError::InvalidLinkTarget);
        }

        /* Verify parent directory */
        let Node::Directory(dir_idx) = self.tree[parent.0 .0] else { unreachable!() };
        let dir = &self.dirs[dir_idx.0];

        if dir.deleted {
            return Err(FileSystemError::NotFound);
        } else if (dir.perms() & PERM_W) == 0 {
            return Err(FileSystemError::InvalidPermissions);
        }

        /* Verify child node */
        if let Some(child_idx) = dir.children.get(name.as_ref()) {
            if !self.is_deleted(*child_idx) {
                return Err(FileSystemError::DuplicateName);
            }
        }

        /* Create link */
        self.dirs[dir_idx.0].children.insert(name.into(), TreeIndex(tree_len));
        self.tree.push(Node::Link(target));

        self.mark_node_dirty(parent.0 .0);

        Ok(())
    }

    pub fn link_file<S: Into<OsString> + AsRef<OsStr>>(
        &mut self,
        parent: DirHandle,
        name: S,
        target: FileHandle,
    ) -> Result<(), FileSystemError> {
        self.check_handle(target)?;
        self.link_node(parent, name, target.0)
    }

    pub fn link_directory<S: Into<OsString> + AsRef<OsStr>>(
        &mut self,
        parent: DirHandle,
        name: S,
        target: DirHandle,
    ) -> Result<(), FileSystemError> {
        self.check_handle(target)?;
        self.link_node(parent, name, target.0)
    }

    fn has_root_as_child_node(&self, node: TreeIndex) -> bool {
        match &self.tree[node.0] {
            Node::Directory(dir_idx) => {
                let dir = &self.dirs[dir_idx.0];

                if dir.deleted {
                    return false;
                }

                for child_idx in dir.children.values() {
                    if child_idx.0 == self.root.0 || self.has_root_as_child_node(*child_idx) {
                        return true;
                    }
                }

                false
            },
            _ => false,
        }
    }

    pub fn dir_is_outside_root(&self, handle: DirHandle) -> Result<bool, FileSystemError> {
        self.check_handle(handle)?;

        let Node::Directory(dir_idx) = &self.tree[handle.0 .0] else { unreachable!() };
        let dir = &self.dirs[dir_idx.0];

        if dir.deleted {
            return Err(FileSystemError::NotFound);
        }

        let outside_root = self.has_root_as_child_node(dir.parent);
        Ok(outside_root)
    }

    pub fn file_is_outside_root(&self, handle: FileHandle) -> Result<bool, FileSystemError> {
        self.check_handle(handle)?;

        let Node::File(file_idx) = &self.tree[handle.0 .0] else { unreachable!() };
        let file = &self.files[file_idx.0];

        if file.deleted {
            return Err(FileSystemError::NotFound);
        }

        let outside_root = self.has_root_as_child_node(file.parent);
        Ok(outside_root)
    }

    pub fn cwd(&self) -> DirHandle {
        DirHandle(self.cwd)
    }

    pub fn root(&self) -> DirHandle {
        DirHandle(self.root)
    }
}

macro_rules! copy_vec {
    ($dst:expr, $src:expr) => {
        $dst.clear();
        $dst.extend_from_slice(&$src);
    };
}

impl Fs {
    pub fn take_snapshot(&mut self, id: SnapshotId) {
        let snapshot = FsSnapshot {
            files: self.files.clone(),
            dirs: self.dirs.clone(),
            tree: self.tree.clone(),
            root: self.root,
            cwd: self.cwd,
            umask: self.umask,
        };
        self.snapshots.insert(id, snapshot);
    }

    pub fn restore_snapshot(&mut self, id: SnapshotId) -> bool {
        let snapshot = match self.snapshots.get(&id) {
            Some(snapshot) => snapshot,
            None => return false,
        };

        if id == self.last_snapshot {
            self.files.truncate(snapshot.files.len());
            self.dirs.truncate(snapshot.dirs.len());
            self.tree.truncate(snapshot.tree.len());

            'outer: for (i, byte) in self.dirty_bits.iter().enumerate() {
                for j in 0..8 {
                    if (*byte & (1 << j)) != 0 {
                        let mut tree_idx = i * 8 + j;

                        if tree_idx >= self.tree.len() {
                            break 'outer;
                        }

                        loop {
                            self.tree[tree_idx] = snapshot.tree[tree_idx].clone();

                            match &snapshot.tree[tree_idx] {
                                Node::Link(link_idx) => {
                                    tree_idx = link_idx.0;
                                    continue;
                                },
                                Node::File(file_idx) => {
                                    self.files[file_idx.0].restore_snapshot(&snapshot.files[file_idx.0]);
                                },
                                Node::Directory(dir_idx) => {
                                    self.dirs[dir_idx.0].restore_snapshot(&snapshot.dirs[dir_idx.0]);
                                },
                            }

                            break;
                        }
                    }
                }
            }
        } else {
            copy_vec!(self.files, snapshot.files);
            copy_vec!(self.dirs, snapshot.dirs);
            copy_vec!(self.tree, snapshot.tree);

            self.last_snapshot = id;
        }

        self.root = snapshot.root;
        self.cwd = snapshot.cwd;
        self.umask = snapshot.umask;

        self.clear_dirty_bits();

        true
    }

    pub fn delete_snapshot(&mut self, id: SnapshotId) -> bool {
        self.snapshots.remove(&id).is_some()
    }
}
