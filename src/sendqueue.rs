use libc::{c_char, c_int, c_uchar, c_uint, c_ushort, sockaddr, timeval, FILE};

use crate::raw;
use crate::Error;
use crate::{Active, Capture};

struct SendQueue {
    squeue: *mut raw::pcap_send_queue,
}

impl SendQueue {
    pub fn new(memsize: c_uint) -> Result<Self, Error> {
        let squeue = unsafe { raw::pcap_sendqueue_alloc(memsize) };
        if squeue == std::ptr::null_mut() {
            return Err(Error::InsufficientMemory);
        }
        Ok(Self { squeue })
    }

    pub fn queue(
        &mut self,
        pkt_header: *const raw::pcap_pkthdr,
        pkt_data: *const c_uchar,
    ) -> Result<(), Error> {
        let res = unsafe { raw::pcap_sendqueue_queue(self.squeue, pkt_header, pkt_data) };
        if res == -1 {}

        Ok(())
    }

    pub fn transmit(&mut self, dev: &mut Capture<Active>, sync: c_int) -> Result<(), Error> {
        let res = raw::pcap_sendqueue_transmit(*dev.handle, self.squeue, sync);

        if res < self.squeue.len {
            return Err(Error::new(raw::pcap_geterr(*dev.handle)));
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
