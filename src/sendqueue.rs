//! WinPcap/npcap sendqueue support module.
//!
//! Sending individual packets through WinPcap/npcap can be stunningly slow, since a user-to-kernel
//! transition is required for each packet transfer.  To alleviate this there's support for
//! queueing up a batch of packets in userland, requiring only a single transition to kernel to
//! transmit them all.

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
    /// Create a new `SendQueue` object with a maximum capacity of `memsize`.
    ///
    /// The buffer size `memsize` must be able to contain both packet headers and actual packet
    /// contents.
    pub fn new(memsize: c_uint) -> Result<Self, Error> {
        let squeue = unsafe { raw::pcap_sendqueue_alloc(memsize) };
        let squeue = NonNull::new(squeue).ok_or(Error::InsufficientMemory)?;

        Ok(Self(squeue))
    }

    pub fn maxlen(&self) -> u32 {
        unsafe { self.0.as_ref().maxlen }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> u32 {
        unsafe { self.0.as_ref().len }
    }

    /// Add a packet to the queue.
    ///
    /// The `ts` argument only needs to be a `Some()` value if the transmission mode will be
    /// synchronous when calling [`SendQueue::transmit()`].
    pub fn queue(&mut self, ts: Option<std::time::Duration>, buf: &[u8]) -> Result<(), Error> {
        let caplen = buf.len().try_into().ok().ok_or(Error::BufferOverflow)?;
        let len = buf.len().try_into().ok().ok_or(Error::BufferOverflow)?;

        let pkthdr = raw::pcap_pkthdr {
            ts: if let Some(ts) = ts {
                libc::timeval {
                    // tv_sec is currently i32 in libc when building for Windows
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
    /// If entire queue was transmitted successfully the queue will be automatically reset.
    ///
    /// If `sync` is set to `Sync::On` the difference between packet header timestamps
    /// will be used as a delay between sending each packet.  If `Sync::Off` is used the packets
    /// will be transmitted with no delay between packets.
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
        unsafe { self.0.as_mut() }.len = 0;
    }
}

impl Drop for SendQueue {
    fn drop(&mut self) {
        unsafe {
            raw::pcap_sendqueue_destroy(self.0.as_ptr());
        }
    }
}
