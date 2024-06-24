use std::{
    fmt::{
        Debug,
        Formatter,
    },
    ops::{
        Index,
        IndexMut,
    },
    slice::SliceIndex,
};

/// A FixedVec is a vector that cannot change its length, only its content
#[derive(Hash)]
pub struct FixedVec<T> {
    inner: Vec<T>,
}

impl<T> FixedVec<T> {
    /// Fixate a vector and return a FixedVec
    pub fn lock<V: Into<Vec<T>>>(inner: V) -> Self {
        Self {
            inner: inner.into(),
        }
    }

    /// Unfixate this vector
    pub fn unlock(self) -> Vec<T> {
        self.inner
    }

    /// The length of this vector
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check whether this vector is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<T, I> Index<I> for FixedVec<T>
where
    I: SliceIndex<[T]>,
{
    type Output = I::Output;

    fn index(&self, index: I) -> &Self::Output {
        self.inner.index(index)
    }
}

impl<T, I> IndexMut<I> for FixedVec<T>
where
    I: SliceIndex<[T]>,
{
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        self.inner.index_mut(index)
    }
}

impl<T> Debug for FixedVec<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "FixedVec")
    }
}
