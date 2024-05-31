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

#[derive(Hash)]
pub struct FixedVec<T> {
    inner: Vec<T>,
}

impl<T> FixedVec<T> {
    pub fn lock<V: Into<Vec<T>>>(inner: V) -> Self {
        Self {
            inner: inner.into(),
        }
    }

    pub fn unlock(self) -> Vec<T> {
        self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

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

#[cfg(test)]
#[test]
fn test_lock() {
    let mut lock = FixedVec::lock("asdf 1234");
    assert_eq!(&lock[0..4], b"asdf");

    for b in &mut lock[0..4] {
        *b = b'A';
    }

    assert_eq!(&lock[..], b"AAAA 1234");
}
