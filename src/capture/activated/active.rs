use std::borrow::Borrow;

#[cfg(not(windows))]
use std::os::unix::io::{AsFd, AsRawFd, BorrowedFd, RawFd};

use crate::{
    Error,
    capture::{Active, Capture},
    raw,
};

impl Capture<Active> {
    /// Sends a packet over this capture handle's interface.
    pub fn sendpacket<B: Borrow<[u8]>>(&mut self, buf: B) -> Result<(), Error> {
        let buf = buf.borrow();
        self.check_err(unsafe {
            raw::pcap_sendpacket(self.handle.as_ptr(), buf.as_ptr() as _, buf.len() as _) == 0
        })
    }

    /// Sends a packet like [`Self::sendpacket()`], but returns `Error::IoError` with a kind of
    /// `WouldBlock` if the device was too busy to take it. Only useful on a non-blocking capture.
    ///
    /// pcap_sendpacket reports every failure the same way, so errno is all we have to tell a busy
    /// device apart from a real error. errno is cleared first, as libpcap rejects some sends
    /// without making a system call and would otherwise leave an old EAGAIN behind. It is then
    /// read before get_err, which allocates and could overwrite it.
    #[cfg(all(target_os = "linux", feature = "capture-stream"))]
    pub(crate) fn sendpacket_nonblock(&mut self, buf: &[u8]) -> Result<(), Error> {
        errno::set_errno(errno::Errno(0));
        let sent = unsafe {
            raw::pcap_sendpacket(self.handle.as_ptr(), buf.as_ptr() as _, buf.len() as _) == 0
        };
        if sent {
            return Ok(());
        }
        let errno = errno::errno().0;
        if errno == libc::EAGAIN || errno == libc::EWOULDBLOCK {
            return Err(Error::IoError(std::io::ErrorKind::WouldBlock));
        }
        Err(self.get_err())
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

#[cfg(not(windows))]
impl AsFd for Capture<Active> {
    /// Returns the file descriptor for a live capture.
    fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: pcap_fileno always succeeds on a live capture,
        // and we know this capture is live due to its State.
        let fd = unsafe { raw::pcap_fileno(self.handle.as_ptr()) };
        assert!(fd != -1, "Unable to get file descriptor for live capture");
        // SAFETY: The lifetime is bound to self, which is correct.
        // We have checked that fd != -1.
        unsafe { BorrowedFd::borrow_raw(fd) }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        capture::testmod::test_capture,
        raw::{
            mock_ffi::*,
            testmod::{RAWMTX, as_pcap_t, geterr_expect},
        },
    };

    use super::*;

    #[test]
    fn test_sendpacket() {
        let _m = RAWMTX.lock();

        let mut dummy: isize = 777;
        let pcap = as_pcap_t(&mut dummy);

        let buffer: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let test_capture = test_capture::<Active>(pcap);
        let mut capture = test_capture.capture;

        let ctx = pcap_sendpacket_context();
        ctx.expect()
            .withf_st(move |arg1, _, _| *arg1 == pcap)
            .return_once(|_, _, _| 0);

        let result = capture.sendpacket(buffer);
        assert!(result.is_ok());

        let ctx = pcap_sendpacket_context();
        ctx.checkpoint();
        ctx.expect()
            .withf_st(move |arg1, _, _| *arg1 == pcap)
            .return_once(|_, _, _| -1);

        let _err = geterr_expect(pcap);

        let result = capture.sendpacket(buffer);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(all(target_os = "linux", feature = "capture-stream"))]
    fn test_sendpacket_nonblock() {
        let _m = RAWMTX.lock();

        let mut dummy: isize = 777;
        let pcap = as_pcap_t(&mut dummy);

        let buffer: [u8; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let test_capture = test_capture::<Active>(pcap);
        let mut capture = test_capture.capture;

        let ctx = pcap_sendpacket_context();
        ctx.expect()
            .withf_st(move |arg1, _, _| *arg1 == pcap)
            .return_once(|_, _, _| 0);

        assert_eq!(capture.sendpacket_nonblock(&buffer), Ok(()));

        // A busy device is not a failure.
        let ctx = pcap_sendpacket_context();
        ctx.checkpoint();
        ctx.expect()
            .withf_st(move |arg1, _, _| *arg1 == pcap)
            .return_once(|_, _, _| {
                errno::set_errno(errno::Errno(libc::EAGAIN));
                -1
            });

        assert_eq!(
            capture.sendpacket_nonblock(&buffer),
            Err(Error::IoError(std::io::ErrorKind::WouldBlock))
        );

        // libpcap can also reject a send without making a system call, leaving errno alone. This
        // case deliberately runs after the one above so that the EAGAIN it set is still there: it
        // must not be mistaken for a busy device, or the sink would wait for a readiness event
        // that is never coming.
        let ctx = pcap_sendpacket_context();
        ctx.checkpoint();
        ctx.expect()
            .withf_st(move |arg1, _, _| *arg1 == pcap)
            .return_once(|_, _, _| -1);

        let _err = geterr_expect(pcap);
        assert!(matches!(
            capture.sendpacket_nonblock(&buffer),
            Err(Error::PcapError(_))
        ));
    }

    #[test]
    fn test_setnonblock() {
        let _m = RAWMTX.lock();

        let mut dummy: isize = 777;
        let pcap = as_pcap_t(&mut dummy);

        let test_capture = test_capture::<Active>(pcap);
        let capture = test_capture.capture;
        assert!(!capture.is_nonblock());

        let ctx = pcap_setnonblock_context();
        ctx.expect()
            .withf_st(move |arg1, arg2, _| (*arg1 == pcap) && (*arg2 == 1))
            .return_once(|_, _, _| 0);

        let capture = capture.setnonblock().unwrap();
        assert!(capture.is_nonblock());
    }

    #[test]
    fn test_setnonblock_error() {
        let _m = RAWMTX.lock();

        let mut dummy: isize = 777;
        let pcap = as_pcap_t(&mut dummy);

        let test_capture = test_capture::<Active>(pcap);
        let capture = test_capture.capture;
        assert!(!capture.nonblock);

        let ctx = pcap_setnonblock_context();
        ctx.expect()
            .withf_st(move |arg1, arg2, _| (*arg1 == pcap) && (*arg2 == 1))
            .return_once(|_, _, _| -1);

        let result = capture.setnonblock();
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(windows))]
    fn test_as_raw_fd() {
        let _m = RAWMTX.lock();

        let mut dummy: isize = 777;
        let pcap = as_pcap_t(&mut dummy);

        let test_capture = test_capture::<Active>(pcap);
        let capture = test_capture.capture;

        let ctx = pcap_fileno_context();
        ctx.expect()
            .withf_st(move |arg1| *arg1 == pcap)
            .return_once(|_| 7);

        assert_eq!(capture.as_raw_fd(), 7);
    }

    #[test]
    #[cfg(not(windows))]
    fn test_as_fd() {
        let _m = RAWMTX.lock();

        let mut dummy: isize = 777;
        let pcap = as_pcap_t(&mut dummy);

        let test_capture = test_capture::<Active>(pcap);
        let capture = test_capture.capture;

        let ctx = pcap_fileno_context();
        ctx.expect()
            .withf_st(move |arg1| *arg1 == pcap)
            .return_once(|_| 7);

        assert_eq!(capture.as_fd().as_raw_fd(), 7);
    }
}
