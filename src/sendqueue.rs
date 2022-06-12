use std::convert::TryInto;
use std::ptr::NonNull;

use libc::c_uint;

use crate::raw;
use crate::Error;
use crate::{Active, Capture};

pub struct SendQueue(NonNull<raw::pcap_send_queue>);

pub enum Sync {
    Off = 0,
    On = 1,
}

impl SendQueue {
    pub fn new(memsize: c_uint) -> Result<Self, Error> {
        let squeue = unsafe { raw::pcap_sendqueue_alloc(memsize) };
        let squeue = NonNull::new(squeue).ok_or(Error::InsufficientMemory)?;

        Ok(Self(squeue))
    }

    pub fn maxlen(&self) -> c_uint {
        unsafe { (*self.0.as_ptr()).maxlen }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> c_uint {
        unsafe { (*self.0.as_ptr()).len }
    }

    /// Add a packet to the queue.
    pub fn queue(&mut self, ts: Option<std::time::Duration>, buf: &[u8]) -> Result<(), Error> {
        let caplen = buf.len().try_into().ok().ok_or(Error::BufferOverflow)?;
        let len = buf.len().try_into().ok().ok_or(Error::BufferOverflow)?;

        let pkthdr = raw::pcap_pkthdr {
            ts: if let Some(ts) = ts {
                libc::timeval {
                    // tv_sec is is currently i32 in libc when building for Windows
                    tv_sec: ts.as_secs() as i32,
                    tv_usec: ts.subsec_micros() as i32,
                }
            } else {
                libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                }
            },
            caplen,
            len,
        };

        let ph = &pkthdr as *const _;
        let res = unsafe { raw::pcap_sendqueue_queue(self.0.as_ptr(), ph, buf.as_ptr()) };
        if res == -1 {
            return Err(Error::InsufficientMemory);
        }

        Ok(())
    }

    /// Transmit the contents of the queue.
    ///
    /// If entire queue was transmitted successfull the queue will be automatically reset.
    pub fn transmit(&mut self, dev: &mut Capture<Active>, sync: Sync) -> Result<(), Error> {
        let res = unsafe {
            raw::pcap_sendqueue_transmit(dev.handle.as_ptr(), self.0.as_ptr(), sync as i32)
        };

        if res < self.len() {
            return unsafe { Err(Error::new(raw::pcap_geterr(dev.handle.as_ptr()))) };
        } else {
            self.reset();
        }

        Ok(())
    }

    pub fn reset(&mut self) {
        unsafe { *self.0.as_ptr() }.len = 0;
    }
}

impl Drop for SendQueue {
    fn drop(&mut self) {
        unsafe {
            raw::pcap_sendqueue_destroy(self.0.as_ptr());
        }
    }
}
