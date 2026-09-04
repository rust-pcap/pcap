//! Support for asynchronous packet transmission.
//!
//! See [`Capture::sink`](super::Capture::sink).
use std::io;
use std::marker::Unpin;
use std::pin::Pin;
use std::task::{self, Poll};

use futures::{Sink, ready};

#[cfg(target_os = "linux")]
use {crate::capture::selectable::SelectableCapture, tokio::io::unix::AsyncFd};

#[cfg(not(target_os = "linux"))]
use tokio::task::coop;

use crate::{
    Error,
    capture::{Active, Capture},
};

impl Capture<Active> {
    /// Returns this capture as a [`futures::Sink`] for sending packets.
    ///
    /// ```no_run
    /// # use futures::SinkExt;
    /// # use pcap::{Active, Capture};
    /// # async fn doc(capture: Capture<Active>) -> Result<(), pcap::Error> {
    /// let mut sink = capture.sink()?;
    /// sink.send(vec![0u8; 64]).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// If this capture is set to be blocking, an error will be returned. On Linux, where the sink
    /// waits for the interface, an error is also returned if the network device does not support
    /// `select()`.
    pub fn sink<C: AsRef<[u8]>>(self) -> Result<PacketSink<C>, Error> {
        if !self.is_nonblock() {
            return Err(Error::NonNonBlock);
        }
        PacketSink::new(self)
    }
}

/// Implement Sink for async use of pcap
///
/// The packet given to `start_send` is held until a later poll can send it, so it is sent without
/// being copied. Only one packet is held at a time. A packet that fails to send is dropped rather
/// than retried, as libpcap does not tell us how much of it made it onto the wire.
///
/// Closing the sink flushes it but does not close the capture, which happens when the
/// [`PacketSink`] is dropped. Once closed, the sink takes no more packets and reports
/// `Error::IoError` with a kind of `BrokenPipe` instead.
///
/// # Warning
///
/// Only on Linux does the capture report when the interface is ready for another packet.
/// Elsewhere the packet is sent from within the poll, and a full transmit queue comes back as an
/// error instead of pausing the sink until there is room.
pub struct PacketSink<C> {
    #[cfg(target_os = "linux")]
    inner: AsyncFd<SelectableCapture<Active>>,
    #[cfg(not(target_os = "linux"))]
    capture: Capture<Active>,
    #[cfg(not(target_os = "linux"))]
    sent_since_yield: u32,
    packet: Option<C>,
    closed: bool,
}

#[cfg(target_os = "linux")]
impl<C> PacketSink<C> {
    pub(crate) fn new(capture: Capture<Active>) -> Result<Self, Error> {
        let capture = SelectableCapture::new(capture)?;
        Ok(PacketSink {
            inner: AsyncFd::with_interest(capture, tokio::io::Interest::WRITABLE)?,
            packet: None,
            closed: false,
        })
    }

    /// Returns a mutable reference to the inner [`Capture`].
    ///
    /// The caller must ensure the capture will not be set to be blocking.
    pub fn capture_mut(&mut self) -> &mut Capture<Active> {
        self.inner.get_mut().get_inner_mut()
    }

    fn poll_send(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Error>>
    where
        C: AsRef<[u8]>,
    {
        let Self { inner, packet, .. } = self;

        loop {
            let buf = match &*packet {
                Some(buf) => buf.as_ref(),
                None => return Poll::Ready(Ok(())),
            };

            let mut guard = ready!(inner.poll_write_ready_mut(cx))?;
            // A busy device goes through the io::Result, so that try_io knows to wait for the
            // next readiness event. A real error goes through the inner Result untouched.
            let result = guard.try_io(|inner| {
                match inner.get_mut().get_inner_mut().sendpacket_nonblock(buf) {
                    Ok(()) => Ok(Ok(())),
                    Err(e @ Error::IoError(io::ErrorKind::WouldBlock)) => {
                        Err(io::Error::new(io::ErrorKind::WouldBlock, e))
                    }
                    Err(e) => Ok(Err(e)),
                }
            });

            match result {
                Ok(result) => {
                    *packet = None;
                    return Poll::Ready(result?);
                }
                Err(_would_block) => continue,
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl<C> PacketSink<C> {
    pub(crate) fn new(capture: Capture<Active>) -> Result<Self, Error> {
        Ok(PacketSink {
            capture,
            sent_since_yield: 0,
            packet: None,
            closed: false,
        })
    }

    /// Returns a mutable reference to the inner [`Capture`].
    ///
    /// The caller must ensure the capture will not be set to be blocking.
    pub fn capture_mut(&mut self) -> &mut Capture<Active> {
        &mut self.capture
    }

    fn poll_send(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), Error>>
    where
        C: AsRef<[u8]>,
    {
        let buf = match &self.packet {
            Some(packet) => packet.as_ref(),
            None => return Poll::Ready(Ok(())),
        };

        // Sending here never waits for the interface, so a sink that is kept fed would never
        // return Pending and the task it runs in would never let the executor poll anything
        // else. Two things stop that. The count applies whoever is driving the sink, which off
        // Linux can be any executor, as it holds nothing of tokio's; 128 is what tokio allows
        // a task between yields. Spending the task's budget as well holds a task that also
        // does tokio I/O to one budget between yields rather than one for each source.
        if self.sent_since_yield == 128 {
            self.sent_since_yield = 0;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let coop = ready!(coop::poll_proceed(cx));
        self.sent_since_yield += 1;

        let result = self.capture.sendpacket(buf);
        coop.made_progress();
        self.packet = None;
        Poll::Ready(result)
    }
}

impl<C> Unpin for PacketSink<C> {}

impl<C: AsRef<[u8]>> Sink<C> for PacketSink<C> {
    type Error = Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), Error>> {
        let sink = Pin::into_inner(self);
        if sink.closed {
            return Poll::Ready(Err(Error::IoError(io::ErrorKind::BrokenPipe)));
        }
        sink.poll_send(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: C) -> Result<(), Error> {
        let sink = Pin::into_inner(self);
        if sink.closed {
            return Err(Error::IoError(io::ErrorKind::BrokenPipe));
        }
        if sink.packet.is_some() {
            // poll_ready did not report the sink ready, so the packet it was given last is
            // still waiting. Keep it: dropping it here would lose a packet the caller has
            // already been told the sink took.
            return Err(Error::IoError(io::ErrorKind::WouldBlock));
        }
        sink.packet = Some(item);
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), Error>> {
        Pin::into_inner(self).poll_send(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Result<(), Error>> {
        let sink = Pin::into_inner(self);
        ready!(sink.poll_send(cx))?;
        sink.closed = true;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use futures::SinkExt;

    use crate::{
        capture::testmod::test_capture,
        raw::{
            mock_ffi::*,
            testmod::{RAWMTX, as_pcap_t, geterr_expect},
        },
    };

    use super::*;

    #[test]
    fn test_sink_error() {
        let _m = RAWMTX.lock();

        let mut dummy: isize = 777;
        let pcap = as_pcap_t(&mut dummy);

        let test_capture = test_capture::<Active>(pcap);
        let capture = test_capture.capture;
        assert!(!capture.is_nonblock());

        let result = capture.sink::<Vec<u8>>();
        assert!(result.is_err());
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use std::os::unix::io::RawFd;

        use crate::raw;

        use super::*;

        // A real file descriptor to stand in for the one libpcap would hand out. AsyncFd registers
        // it for real, so the sink takes the same path it would with a live capture.
        struct FdPair([RawFd; 2]);

        impl FdPair {
            fn new() -> Self {
                let mut fds: [RawFd; 2] = [-1, -1];
                let rc = unsafe {
                    libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr())
                };
                assert_eq!(rc, 0, "Unable to create a socketpair");
                Self(fds)
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
        // when the sink is dropped.
        fn test_sink(
            pcap: *mut raw::pcap_t,
            capture: Capture<Active>,
            fd: RawFd,
        ) -> PacketSink<Vec<u8>> {
            let ctx = raw::pcap_get_selectable_fd_context();
            ctx.expect()
                .withf_st(move |arg1| *arg1 == pcap)
                .return_once(move |_| fd);

            PacketSink::new(capture).unwrap()
        }

        #[tokio::test]
        async fn test_sink_ok() {
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

            let mut sink = capture.sink::<Vec<u8>>().unwrap();
            assert!(sink.capture_mut().is_nonblock());

            // Closing flushes the sink. The capture stays open until the sink is dropped.
            sink.close().await.unwrap();
        }

        #[tokio::test]
        async fn test_sink_sends() {
            let _m = RAWMTX.lock();

            let mut dummy: isize = 777;
            let pcap = as_pcap_t(&mut dummy);
            let fds = FdPair::new();

            let test_capture = test_capture::<Active>(pcap);
            let mut sink = test_sink(pcap, test_capture.capture, fds.0[0]);

            let ctx = pcap_sendpacket_context();
            ctx.expect()
                .withf_st(move |arg1, _, arg3| (*arg1 == pcap) && (*arg3 == 4))
                .return_once(|_, _, _| 0);

            sink.send(vec![1, 2, 3, 4]).await.unwrap();
            assert!(sink.packet.is_none());

            let ctx = pcap_sendpacket_context();
            ctx.checkpoint();
            ctx.expect()
                .withf_st(move |arg1, _, _| *arg1 == pcap)
                .return_once(|_, _, _| {
                    errno::set_errno(errno::Errno(libc::EINVAL));
                    -1
                });

            let _err = geterr_expect(pcap);

            let result = sink.send(vec![1, 2, 3, 4]).await;
            assert!(matches!(result, Err(Error::PcapError(_))));

            // The failed packet is dropped, so the sink can be used again.
            assert!(sink.packet.is_none());
        }

        #[tokio::test]
        async fn test_sink_backpressure() {
            let _m = RAWMTX.lock();

            let mut dummy: isize = 777;
            let pcap = as_pcap_t(&mut dummy);
            let fds = FdPair::new();

            let test_capture = test_capture::<Active>(pcap);
            let mut sink = test_sink(pcap, test_capture.capture, fds.0[0]);

            let ctx = pcap_sendpacket_context();
            ctx.expect()
                .withf_st(move |arg1, _, _| *arg1 == pcap)
                .returning(|_, _, _| {
                    errno::set_errno(errno::Errno(libc::EAGAIN));
                    -1
                });

            // Wait until the socketpair is reported writable, so the poll below gets past the
            // readiness check and asks libpcap to send. The guard is dropped without clearing,
            // which leaves the readiness in place.
            drop(sink.inner.writable().await.unwrap());

            sink.packet = Some(vec![1, 2, 3]);

            // A busy device is not an error. The sink waits and the packet stays queued.
            let poll = futures::future::poll_fn(|cx| Poll::Ready(sink.poll_send(cx))).await;
            assert!(poll.is_pending());
            assert_eq!(sink.packet, Some(vec![1, 2, 3]));
        }

        #[tokio::test]
        async fn test_sink_closed() {
            let _m = RAWMTX.lock();

            let mut dummy: isize = 777;
            let pcap = as_pcap_t(&mut dummy);
            let fds = FdPair::new();

            let test_capture = test_capture::<Active>(pcap);
            let mut sink = test_sink(pcap, test_capture.capture, fds.0[0]);

            sink.close().await.unwrap();

            // There is no pcap_sendpacket expectation, so a send here would fail the test.
            assert_eq!(
                sink.send(vec![1, 2, 3, 4]).await,
                Err(Error::IoError(io::ErrorKind::BrokenPipe))
            );
            assert!(sink.packet.is_none());
        }

        #[tokio::test]
        async fn test_sink_start_send_twice() {
            let _m = RAWMTX.lock();

            let mut dummy: isize = 777;
            let pcap = as_pcap_t(&mut dummy);
            let fds = FdPair::new();

            let test_capture = test_capture::<Active>(pcap);
            let mut sink = test_sink(pcap, test_capture.capture, fds.0[0]);

            Pin::new(&mut sink).start_send(vec![1, 2, 3, 4]).unwrap();

            // Nothing has sent the first packet yet, so the second one is refused rather than
            // put in its place.
            assert_eq!(
                Pin::new(&mut sink).start_send(vec![5, 6, 7]),
                Err(Error::IoError(io::ErrorKind::WouldBlock))
            );
            assert_eq!(sink.packet, Some(vec![1, 2, 3, 4]));

            let ctx = pcap_sendpacket_context();
            ctx.expect()
                .withf_st(move |arg1, _, arg3| (*arg1 == pcap) && (*arg3 == 4))
                .return_once(|_, _, _| 0);

            sink.flush().await.unwrap();
            assert!(sink.packet.is_none());
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_sink_ok() {
        let _m = RAWMTX.lock();

        let mut dummy: isize = 777;
        let pcap = as_pcap_t(&mut dummy);

        let test_capture = test_capture::<Active>(pcap);

        let ctx = pcap_setnonblock_context();
        ctx.expect()
            .withf_st(move |arg1, arg2, _| (*arg1 == pcap) && (*arg2 == 1))
            .return_once(|_, _, _| 0);

        let capture = test_capture.capture.setnonblock().unwrap();

        let mut sink = capture.sink::<Vec<u8>>().unwrap();
        assert!(sink.capture_mut().is_nonblock());

        // Closing flushes the sink. The capture stays open until the sink is dropped.
        sink.close().await.unwrap();
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_sink_sends() {
        let _m = RAWMTX.lock();

        let mut dummy: isize = 777;
        let pcap = as_pcap_t(&mut dummy);

        let test_capture = test_capture::<Active>(pcap);
        let mut sink = PacketSink::new(test_capture.capture).unwrap();

        let ctx = pcap_sendpacket_context();
        ctx.expect()
            .withf_st(move |arg1, _, arg3| (*arg1 == pcap) && (*arg3 == 4))
            .return_once(|_, _, _| 0);

        sink.send(vec![1, 2, 3, 4]).await.unwrap();
        assert!(sink.packet.is_none());

        let ctx = pcap_sendpacket_context();
        ctx.checkpoint();
        ctx.expect()
            .withf_st(move |arg1, _, _| *arg1 == pcap)
            .return_once(|_, _, _| -1);

        let _err = geterr_expect(pcap);

        let result = sink.send(vec![1, 2, 3, 4]).await;
        assert!(matches!(result, Err(Error::PcapError(_))));
        assert!(sink.packet.is_none());
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_sink_closed() {
        let _m = RAWMTX.lock();

        let mut dummy: isize = 777;
        let pcap = as_pcap_t(&mut dummy);

        let test_capture = test_capture::<Active>(pcap);
        let mut sink = PacketSink::new(test_capture.capture).unwrap();

        sink.close().await.unwrap();

        // There is no pcap_sendpacket expectation, so a send here would fail the test.
        assert_eq!(
            sink.send(vec![1, 2, 3, 4]).await,
            Err(Error::IoError(io::ErrorKind::BrokenPipe))
        );
        assert!(sink.packet.is_none());
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_sink_start_send_twice() {
        let _m = RAWMTX.lock();

        let mut dummy: isize = 777;
        let pcap = as_pcap_t(&mut dummy);

        let test_capture = test_capture::<Active>(pcap);
        let mut sink = PacketSink::new(test_capture.capture).unwrap();

        Pin::new(&mut sink).start_send(vec![1, 2, 3, 4]).unwrap();

        // Nothing has sent the first packet yet, so the second one is refused rather than put
        // in its place.
        assert_eq!(
            Pin::new(&mut sink).start_send(vec![5, 6, 7]),
            Err(Error::IoError(io::ErrorKind::WouldBlock))
        );
        assert_eq!(sink.packet, Some(vec![1, 2, 3, 4]));

        let ctx = pcap_sendpacket_context();
        ctx.expect()
            .withf_st(move |arg1, _, arg3| (*arg1 == pcap) && (*arg3 == 4))
            .return_once(|_, _, _| 0);

        sink.flush().await.unwrap();
        assert!(sink.packet.is_none());
    }

    // Deliberately not a tokio test. The sink is a futures::Sink and off Linux it holds nothing
    // of tokio's, so it has to give up its turn whatever executor is driving it.
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn test_sink_yields() {
        let _m = RAWMTX.lock();

        let mut dummy: isize = 777;
        let pcap = as_pcap_t(&mut dummy);

        let test_capture = test_capture::<Active>(pcap);
        let mut sink = PacketSink::new(test_capture.capture).unwrap();

        let ctx = pcap_sendpacket_context();
        ctx.expect()
            .withf_st(move |arg1, _, _| *arg1 == pcap)
            .returning(|_, _, _| 0);

        let waker = futures::task::noop_waker();
        let mut cx = task::Context::from_waker(&waker);

        // Keep the sink fed and poll it until it asks to be polled again later. One that never
        // does keeps the thread to itself for as long as there are packets to send.
        let mut sends = 0;
        loop {
            sink.packet = Some(vec![1, 2, 3, 4]);
            if sink.poll_send(&mut cx).is_pending() {
                break;
            }
            sends += 1;
            assert!(sends < 10_000, "the sink never gave up its turn");
        }
        assert_eq!(sends, 128);

        // The packet the sink yielded on is still there for the poll after it.
        assert_eq!(sink.packet, Some(vec![1, 2, 3, 4]));
    }

    // Under tokio the sink spends the task's budget too, so a task that has already spent some
    // of it elsewhere gets its turn back sooner than the count alone would give it.
    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn test_sink_yields_on_task_budget() {
        let _m = RAWMTX.lock();

        let mut dummy: isize = 777;
        let pcap = as_pcap_t(&mut dummy);

        let test_capture = test_capture::<Active>(pcap);
        let mut sink = PacketSink::new(test_capture.capture).unwrap();

        let ctx = pcap_sendpacket_context();
        ctx.expect()
            .withf_st(move |arg1, _, _| *arg1 == pcap)
            .returning(|_, _, _| 0);

        // Spend half the budget on something that is not the sink.
        for _ in 0..64 {
            coop::consume_budget().await;
        }

        let mut sends = 0;
        loop {
            sink.packet = Some(vec![1, 2, 3, 4]);
            if futures::future::poll_fn(|cx| Poll::Ready(sink.poll_send(cx)))
                .await
                .is_pending()
            {
                break;
            }
            sends += 1;
            assert!(sends < 10_000, "the sink never gave up its turn");
        }
        assert!(
            sends < 128,
            "the sink sent {sends} before yielding, so it kept a budget of its own"
        );
    }
}
