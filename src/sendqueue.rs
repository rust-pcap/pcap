use std::convert::TryInto;
use std::time::{SystemTime, UNIX_EPOCH};

use libc::{c_int, c_uint};

use crate::raw;
use crate::Error;
use crate::{Active, Capture};

pub struct SendQueue {
    squeue: *mut raw::pcap_send_queue,
    sync: c_int,
}

impl SendQueue {
    pub fn new(memsize: c_uint) -> Result<Self, Error> {
        let squeue = unsafe { raw::pcap_sendqueue_alloc(memsize) };
        if squeue == std::ptr::null_mut() {
            return Err(Error::InsufficientMemory);
        }
        Ok(Self { squeue, sync: 0 })
    }

    pub fn maxlen(&self) -> c_int {
        unsafe { (*self.squeue).maxlen() }
    }

    pub fn len(&self) -> c_int {
        unsafe { (*self.squeue).len() }
    }

    pub fn sync(&mut self, sync: bool) {
        self.sync = if sync { 1 } else { 0 }
    }

    /// Add a packet to the queue.
    pub fn queue(&mut self, buf: &[u8]) -> Result<(), Error> {
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");

        let s = since_the_epoch.as_secs();
        let us = since_the_epoch.subsec_micros();

        let pkthdr = raw::pcap_pkthdr {
            ts: libc::timeval {
                tv_sec: s as i32,
                tv_usec: us as i32,
            },
            caplen: buf.len() as u32,
            len: buf.len() as u32,
        };

        let ph = &pkthdr as *const _;
        let res = unsafe { raw::pcap_sendqueue_queue(self.squeue, ph, buf.as_ptr()) };
        if res == -1 {
            return Err(Error::InsufficientMemory);
        }

        Ok(())
    }

    /// Transmit the contents of the queue.
    pub fn transmit(&mut self, dev: &mut Capture<Active>) -> Result<(), Error> {
        let res = unsafe { raw::pcap_sendqueue_transmit(*dev.handle, self.squeue, self.sync) };

        // ToDo: Fix unwrap()
        if res < self.len().try_into().unwrap() {
            return unsafe { Err(Error::new(raw::pcap_geterr(*dev.handle))) };
        }

        Ok(())
    }
}

impl Drop for SendQueue {
    fn drop(&mut self) {
        unsafe {
            raw::pcap_sendqueue_destroy(self.squeue);
        }
    }
}
