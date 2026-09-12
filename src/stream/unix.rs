//! Support for asynchronous packet iteration.
//!
//! See [`Capture::stream`](super::Capture::stream).
use std::io;
use std::marker::Unpin;
use std::pin::Pin;
use std::task::{self, Poll};

use futures::ready;
use tokio::io::unix::AsyncFd;

use crate::{
    Error,
    capture::{Activated, Capture, selectable::SelectableCapture},
    codec::PacketCodec,
};

/// Implement Stream for async use of pcap
pub struct PacketStream<T: Activated + ?Sized, C> {
    inner: AsyncFd<SelectableCapture<T>>,
    codec: C,
}

impl<T: Activated + ?Sized, C> PacketStream<T, C> {
    pub(crate) fn new(capture: Capture<T>, codec: C) -> Result<Self, Error> {
        let capture = SelectableCapture::new(capture)?;
        Ok(PacketStream {
            inner: AsyncFd::with_interest(capture, tokio::io::Interest::READABLE)?,
            codec,
        })
    }

    /// Returns a mutable reference to the inner [`Capture`].
    ///
    /// The caller must ensure the capture will not be set to be blocking.
    pub fn capture_mut(&mut self) -> &mut Capture<T> {
        self.inner.get_mut().get_inner_mut()
    }
}

impl<T: Activated + ?Sized, C> Unpin for PacketStream<T, C> {}

impl<T: Activated + ?Sized, C: PacketCodec> futures::Stream for PacketStream<T, C> {
    type Item = Result<C::Item, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut task::Context) -> Poll<Option<Self::Item>> {
        let stream = Pin::into_inner(self);
        let codec = &mut stream.codec;

        loop {
            let mut guard = ready!(stream.inner.poll_read_ready_mut(cx))?;
            match guard.try_io(
                |inner| match inner.get_mut().get_inner_mut().next_packet() {
                    Ok(p) => Ok(Ok(codec.decode(p))),
                    Err(e @ Error::TimeoutExpired) => {
                        Err(io::Error::new(io::ErrorKind::WouldBlock, e))
                    }
                    Err(e) => Ok(Err(e)),
                },
            ) {
                Ok(result) => {
                    return Poll::Ready(Some(result?));
                }
                Err(_would_block) => continue,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::io::RawFd;

    use futures::{Stream, StreamExt};

    use crate::{
        capture::{
            Active,
            activated::testmod::{PACKET, next_ex_expect},
            testmod::test_capture,
        },
        codec::testmod::Codec,
        raw::{
            self,
            testmod::{RAWMTX, as_pcap_t, geterr_expect},
        },
    };

    use super::*;

    // A real file descriptor to stand in for the one libpcap would hand out. AsyncFd registers it
    // for real, so the stream takes the same path it would with a live capture.
    struct FdPair([RawFd; 2]);

    impl FdPair {
        fn new() -> Self {
            let mut fds: [RawFd; 2] = [-1, -1];
            let rc =
                unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
            assert_eq!(rc, 0, "Unable to create a socketpair");
            Self(fds)
        }

        // The stream waits for the capture to be readable before it asks libpcap for a packet, so
        // there has to be something to read.
        fn make_readable(&self) {
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

    // The caller holds on to the TestCapture, which owns the pcap_close expectation that fires
    // when the stream is dropped.
    fn test_stream(
        pcap: *mut raw::pcap_t,
        capture: Capture<Active>,
        fd: RawFd,
    ) -> PacketStream<Active, Codec> {
        let ctx = raw::pcap_get_selectable_fd_context();
        ctx.expect()
            .withf_st(move |arg1| *arg1 == pcap)
            .return_once(move |_| fd);

        PacketStream::new(capture, Codec).unwrap()
    }

    #[tokio::test]
    async fn test_stream_ok() {
        let _m = RAWMTX.lock();

        let mut dummy: isize = 777;
        let pcap = as_pcap_t(&mut dummy);
        let fds = FdPair::new();
        let fd = fds.0[0];

        let test_capture = test_capture::<Active>(pcap);

        let ctx = raw::pcap_setnonblock_context();
        ctx.expect()
            .withf_st(move |arg1, arg2, _| (*arg1 == pcap) && (*arg2 == 1))
            .return_once(|_, _, _| 0);

        let capture = test_capture.capture.setnonblock().unwrap();

        let ctx = raw::pcap_get_selectable_fd_context();
        ctx.expect()
            .withf_st(move |arg1| *arg1 == pcap)
            .return_once(move |_| fd);

        let mut stream = capture.stream(Codec).unwrap();
        assert!(stream.capture_mut().is_nonblock());
    }

    #[tokio::test]
    async fn test_stream_reads() {
        let _m = RAWMTX.lock();

        let mut dummy: isize = 777;
        let pcap = as_pcap_t(&mut dummy);
        let fds = FdPair::new();

        let test_capture = test_capture::<Active>(pcap);
        let mut stream = test_stream(pcap, test_capture.capture, fds.0[0]);

        fds.make_readable();

        let _nxt = next_ex_expect(pcap);

        let next_packet = stream.next().await.unwrap().unwrap();
        assert_eq!(next_packet.header, *PACKET.header);
        assert_eq!(*next_packet.data, *PACKET.data);

        let ctx = raw::pcap_next_ex_context();
        ctx.checkpoint();
        ctx.expect()
            .withf_st(move |arg1, _, _| *arg1 == pcap)
            .return_once(|_, _, _| -1);

        let _err = geterr_expect(pcap);

        let result = stream.next().await.unwrap();
        assert!(matches!(result, Err(Error::PcapError(_))));
    }

    #[tokio::test]
    async fn test_stream_timeout() {
        let _m = RAWMTX.lock();

        let mut dummy: isize = 777;
        let pcap = as_pcap_t(&mut dummy);
        let fds = FdPair::new();

        let test_capture = test_capture::<Active>(pcap);
        let mut stream = test_stream(pcap, test_capture.capture, fds.0[0]);

        fds.make_readable();

        let ctx = raw::pcap_next_ex_context();
        ctx.expect()
            .withf_st(move |arg1, _, _| *arg1 == pcap)
            .return_once(|_, _, _| 0);

        // Wait until the socketpair is reported readable, so the poll below gets past the
        // readiness check and asks libpcap for a packet. The guard is dropped without clearing,
        // which leaves the readiness in place.
        drop(stream.inner.readable().await.unwrap());

        // A timeout is not the end of the stream. It waits for the capture to be readable again.
        let poll =
            futures::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut stream).poll_next(cx))).await;
        assert!(poll.is_pending());
    }
}
