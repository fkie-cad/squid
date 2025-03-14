use std::{
    hash::{
        Hash,
        Hasher,
    },
    slice::{
        Iter,
        IterMut,
    },
};

/// The ID of an element in the ProcessImage
pub type Id = usize;

pub(crate) trait HasIdMut {
    fn id_mut(&mut self) -> &mut Id;
}

/// This trait provides access to the ID of elements in the process image
pub trait HasId {
    /// Retrieve the ID of this element
    fn id(&self) -> Id;
}

#[derive(Debug, Clone)]
pub(crate) struct IdFactory {
    cursor: Id,
}

impl IdFactory {
    pub(crate) fn new() -> Self {
        Self {
            cursor: Id::default().wrapping_add(1),
        }
    }

    pub(crate) fn next(&mut self) -> Id {
        let ret = self.cursor;
        self.cursor = ret.checked_add(1).expect("Ran out of possible ID values");
        ret
    }

    pub(crate) fn reset(&mut self) {
        self.cursor = Id::default().wrapping_add(1);
    }
}

pub(crate) type IdMapValues<'a, T> = Iter<'a, T>;
pub(crate) type IdMapValuesMut<'a, T> = IterMut<'a, T>;

#[derive(Clone, Debug)]
pub(crate) struct IdMap<T>
where
    T: HasId + HasIdMut + Hash,
{
    data: Vec<T>,
    factory: IdFactory,
}

impl<T> Hash for IdMap<T>
where
    T: HasId + HasIdMut + Hash,
{
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_usize(self.data.len());
        for elem in &self.data {
            elem.hash(state);
        }
    }
}

impl<T> IdMap<T>
where
    T: HasId + HasIdMut + Hash,
{
    pub(crate) fn new() -> Self {
        Self {
            data: Vec::new(),
            factory: IdFactory::new(),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.data.clear();
        self.factory.reset();
    }

    pub(crate) fn reserve_id(&mut self, elem: &mut T) -> Id {
        let mut id = elem.id();

        if id == Id::default() {
            id = self.factory.next();
            *elem.id_mut() = id;
        }

        id
    }

    pub(crate) fn insert(&mut self, mut elem: T) -> Id {
        let id = self.reserve_id(&mut elem);
        self.data.push(elem);
        id
    }

    pub(crate) fn get(&self, id: Id) -> Option<&T> {
        self.data.iter().find(|&elem| elem.id() == id)
    }

    pub(crate) fn get_mut(&mut self, id: Id) -> Option<&mut T> {
        self.data.iter_mut().find(|elem| elem.id() == id)
    }

    pub(crate) fn values(&self) -> IdMapValues<T> {
        self.data.iter()
    }

    pub(crate) fn values_mut(&mut self) -> IdMapValuesMut<T> {
        self.data.iter_mut()
    }

    pub(crate) fn get_at(&self, idx: usize) -> Option<&T> {
        self.data.get(idx)
    }

    pub(crate) fn get_at_mut(&mut self, idx: usize) -> Option<&mut T> {
        self.data.get_mut(idx)
    }

    pub(crate) fn insert_at(&mut self, idx: usize, mut elem: T) -> Id {
        let id = self.reserve_id(&mut elem);
        self.data.insert(idx, elem);
        id
    }

    pub(crate) fn remove_at(&mut self, idx: usize) -> T {
        self.data.remove(idx)
    }

    pub(crate) fn len(&self) -> usize {
        self.data.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

macro_rules! idmap_functions {
    ($parent:ty, $child:ty, $suffix:ident) => {
        /// Accessor methods that handle the children of this process image element
        impl $parent {
            /// Get the cursor of this process image element
            pub fn cursor(&self) -> usize {
                self.cursor
            }

            /// Set the cursor of this process image element
            pub fn set_cursor(&mut self, cursor: usize) {
                self.cursor = cursor;
            }

            /// Move the cursor of this process image element to the end of its children list.
            /// This enables appending children.
            pub fn move_cursor_beyond_end(&mut self) {
                self.cursor = self.idmap.len();
            }

            /// Increment the cursor of this process image element or return `false` if the cursor
            /// is already at the last child
            pub fn move_cursor_forward(&mut self) -> bool {
                if self.cursor >= self.idmap.len().saturating_sub(1) {
                    false
                } else {
                    self.cursor += 1;
                    true
                }
            }

            /// Decrement the cursor of this process image element or return `false` if it's already
            /// at the first child
            pub fn move_cursor_backwards(&mut self) -> bool {
                if self.cursor == 0 {
                    false
                } else {
                    self.cursor -= 1;
                    true
                }
            }

            /// Retrieve the child with the given ID of this process image element
            pub fn $suffix(&self, id: Id) -> Option<&$child> {
                self.idmap.get(id)
            }

            paste! {
                /// Get the number of children for this process image element
                pub fn [<num_ $suffix s>](&self) -> usize {
                    self.idmap.len()
                }

                /// Get the child at the current cursor position for this process image element
                pub fn [<cursor_ $suffix>](&self) -> Option<&$child> {
                    self.idmap.get_at(self.cursor)
                }

                /// Get the child at the current cursor position for this process image element
                pub fn [<cursor_ $suffix _mut>](&mut self) -> Option<&mut $child> {
                    self.idmap.get_at_mut(self.cursor)
                }

                /// Insert the given child into the list of children at the current cursor position for this process image element
                pub fn [<insert_ $suffix>](&mut self, child: $child) -> Id {
                    self.idmap.insert_at(self.cursor, child)
                }

                /// Delete the child at the current cursor position of this process image element and return it
                pub fn [<delete_ $suffix>](&mut self) -> $child {
                    self.idmap.remove_at(self.cursor)
                }

                /// Iterate over all children of this process image element independent of the current cursor position
                pub fn [<iter_ $suffix s>](&self) -> IdMapValues<$child> {
                    self.idmap.values()
                }

                /// Iterate over all children of this process image element independent of the current cursor position
                pub fn [<iter_ $suffix s_mut>](&mut self) -> IdMapValuesMut<$child> {
                    self.idmap.values_mut()
                }

                /// Retrieve the child with the given ID of this process image element
                pub fn [<$suffix _mut>](&mut self, id: Id) -> Option<&mut $child> {
                    self.idmap.get_mut(id)
                }
            }
        }
    };
}
pub(crate) use idmap_functions;
