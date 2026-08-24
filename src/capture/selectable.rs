use std::os::unix::io::{AsRawFd, RawFd};

use crate::{
    Error,
    capture::{Activated, Capture, State},
    raw,
};

/// Newtype [`Capture`] wrapper that exposes `pcap_get_selectable_fd()`.
pub struct SelectableCapture<T: State + ?Sized> {
    inner: Capture<T>,
    fd: RawFd,
}

impl<T: Activated + ?Sized> SelectableCapture<T> {
    pub fn new(capture: Capture<T>) -> Result<Self, Error> {
        let fd = unsafe { raw::pcap_get_selectable_fd(capture.as_ptr()) };
        if fd == -1 {
            return Err(Error::InvalidRawFd);
        }
        Ok(Self { inner: capture, fd })
    }

    pub fn get_inner_mut(&mut self) -> &mut Capture<T> {
        &mut self.inner
    }
}

impl<T: Activated + ?Sized> AsRawFd for SelectableCapture<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

// GRCOV_EXCL_START
#[cfg(test)]
pub mod testmod {
    use super::*;

    // A real file descriptor to stand in for the one libpcap would hand out. AsyncFd registers it
    // for real, so the sink and the stream take the same path they would with a live capture.
    pub struct FdPair(pub [RawFd; 2]);

    impl FdPair {
        pub fn new() -> Self {
            let mut fds: [RawFd; 2] = [-1, -1];
            let rc =
                unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
            assert_eq!(rc, 0, "Unable to create a socketpair");
            Self(fds)
        }

        // The stream waits for the capture to be readable before it asks libpcap for a packet, so
        // there has to be something to read.
        pub fn make_readable(&self) {
            let byte = 0u8;
            let rc = unsafe { libc::write(self.0[1], &byte as *const u8 as _, 1) };
            assert_eq!(rc, 1, "Unable to write to the socketpair");
        }
    }

    impl Drop for FdPair {
        fn drop(&mut self) {
            for fd in self.0 {
                unsafe { libc::close(fd) };
            }
        }
    }
}
// GRCOV_EXCL_STOP

#[cfg(test)]
mod tests {
    use crate::{
        capture::{Active, testmod::test_capture},
        raw::testmod::{RAWMTX, as_pcap_t},
    };

    use super::*;

    #[test]
    fn test_selectable_capture() {
        let _m = RAWMTX.lock();

        let mut dummy: isize = 777;
        let pcap = as_pcap_t(&mut dummy);

        let test_capture = test_capture::<Active>(pcap);
        let capture = test_capture.capture;

        let ctx = raw::pcap_get_selectable_fd_context();
        ctx.expect()
            .withf_st(move |arg1| *arg1 == pcap)
            .return_once(|_| 5);

        let mut selectable = SelectableCapture::new(capture).unwrap();
        assert!(!selectable.get_inner_mut().is_nonblock());
        assert_eq!(selectable.as_raw_fd(), 5);
    }

    #[test]
    fn test_selectable_capture_error() {
        let _m = RAWMTX.lock();

        let mut dummy: isize = 777;
        let pcap = as_pcap_t(&mut dummy);

        let test_capture = test_capture::<Active>(pcap);
        let capture = test_capture.capture;

        let ctx = raw::pcap_get_selectable_fd_context();
        ctx.expect()
            .withf_st(move |arg1| *arg1 == pcap)
            .return_once(|_| -1);

        let result = SelectableCapture::new(capture);
        assert!(result.is_err());
    }
}
