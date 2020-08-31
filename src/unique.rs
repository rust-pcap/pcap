#![allow(dead_code)]

use std::fmt;
use std::marker::PhantomData;
use std::ops::Deref;

pub struct Unique<T: ?Sized> {
    pointer: *const T,
    _marker: PhantomData<T>,
}

unsafe impl<T: Send + ?Sized> Send for Unique<T> {}
unsafe impl<T: Sync + ?Sized> Sync for Unique<T> {}

impl<T: ?Sized> Unique<T> {
    pub unsafe fn new(ptr: *mut T) -> Unique<T> {
        Unique {
            pointer: ptr,
            _marker: PhantomData,
        }
    }
    pub unsafe fn get(&self) -> &T {
        &*self.pointer
    }
    pub unsafe fn get_mut(&mut self) -> &mut T {
        &mut ***self
    }
}

impl<T: ?Sized> Deref for Unique<T> {
    type Target = *mut T;

    #[inline]
    fn deref(&self) -> &*mut T {
        unsafe { &*(&self.pointer as *const *const T as *const *mut T) }
    }
}

impl<T> fmt::Pointer for Unique<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Pointer::fmt(&self.pointer, f)
    }
}
