use std::borrow::Borrow;

#[cfg(not(windows))]
use std::os::unix::io::{AsRawFd, RawFd};

use crate::{
    capture::{Active, Capture},
    raw, Error,
};

impl Capture<Active> {
    /// Sends a packet over this capture handle's interface.
    pub fn sendpacket<B: Borrow<[u8]>>(&mut self, buf: B) -> Result<(), Error> {
        let buf = buf.borrow();
        self.check_err(unsafe {
            raw::pcap_sendpacket(self.handle.as_ptr(), buf.as_ptr() as _, buf.len() as _) == 0
        })
    }

    /// Set the capture to be non-blocking. When this is set, [`Self::next_packet()`] may return an
    /// error indicating that there is no packet available to be read.
    pub fn setnonblock(mut self) -> Result<Capture<Active>, Error> {
        Error::with_errbuf(|err| unsafe {
            if raw::pcap_setnonblock(self.handle.as_ptr(), 1, err) != 0 {
                return Err(Error::new(err));
            }
            self.nonblock = true;
            Ok(self)
        })
    }
}

#[cfg(not(windows))]
impl AsRawFd for Capture<Active> {
    /// Returns the file descriptor for a live capture.
    fn as_raw_fd(&self) -> RawFd {
        let fd = unsafe { raw::pcap_fileno(self.handle.as_ptr()) };
        assert!(fd != -1, "Unable to get file descriptor for live capture");
        fd
    }
}
