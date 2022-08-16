#![allow(dead_code)]

use std::ptr::NonNull;

/// MUST NOT IMPLEMENT COPY or CLONE
/// This struct OWN the pointer
/// and have a F implementation that will call F to free the pointer.
#[derive(Debug)]
pub struct Handle<T> {
    handle: NonNull<T>,
    drop: unsafe extern "C" fn(*mut T),
}

impl<T> Handle<T> {
    pub fn new(handle: NonNull<T>, drop: unsafe extern "C" fn(*mut T)) -> Self {
        Self { handle, drop }
    }

    pub fn as_ptr(&self) -> *mut T {
        self.handle.as_ptr()
    }

    pub unsafe fn as_ref(&self) -> &T {
        self.handle.as_ref()
    }

    pub unsafe fn as_mut(&mut self) -> &mut T {
        self.handle.as_mut()
    }
}

impl<T> Drop for Handle<T> {
    fn drop(&mut self) {
        unsafe { (self.drop)(self.as_ptr()) }
    }
}
