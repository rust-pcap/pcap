use std::convert::TryInto;
use std::ptr::NonNull;
use std::time::{SystemTime, UNIX_EPOCH};

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

    pub fn len(&self) -> c_uint {
        unsafe { (*self.0.as_ptr()).len }
    }

    /// Add a packet to the queue.
    pub fn queue(&mut self, buf: &[u8]) -> Result<(), Error> {
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        let s = since_the_epoch.as_secs();
        let us = since_the_epoch.subsec_micros();

        let caplen = buf.len().try_into().ok().ok_or(Error::BufferOverflow)?;
        let len = buf.len().try_into().ok().ok_or(Error::BufferOverflow)?;

        let pkthdr = raw::pcap_pkthdr {
            ts: libc::timeval {
                tv_sec: s as i32,
                tv_usec: us as i32,
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
    pub fn transmit(&mut self, dev: &mut Capture<Active>, sync: Sync) -> Result<(), Error> {
        let res = unsafe {
            raw::pcap_sendqueue_transmit(dev.handle.as_ptr(), self.0.as_ptr(), sync as i32)
        };

        if res < self.len() {
            return unsafe { Err(Error::new(raw::pcap_geterr(dev.handle.as_ptr()))) };
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
