//! Support for asynchronous packet iteration.
//!
//! See [`Capture::stream`](super::Capture::stream).
use std::io;
use std::marker::Unpin;
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{self, Poll};

use futures::ready;
use tokio::io::unix::AsyncFd;

use crate::{
    core::{
        capture::{Activated, Capture, State},
        codec::PacketCodec,
    },
    raw, Error,
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
    /// The caller must ensure the capture will not be set to be
    /// blocking.
    pub fn capture_mut(&mut self) -> &mut Capture<T> {
        &mut self.inner.get_mut().inner
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
            match guard.try_io(|inner| match inner.get_mut().inner.next_packet() {
                Ok(p) => Ok(Ok(codec.decode(p))),
                Err(e @ Error::TimeoutExpired) => Err(io::Error::new(io::ErrorKind::WouldBlock, e)),
                Err(e) => Ok(Err(e)),
            }) {
                Ok(result) => {
                    return Poll::Ready(Some(result?));
                }
                Err(_would_block) => continue,
            }
        }
    }
}

/// Newtype [`Capture`] wrapper that exposes `pcap_get_selectable_fd()`.
struct SelectableCapture<T: State + ?Sized> {
    inner: Capture<T>,
    fd: RawFd,
}

impl<T: Activated + ?Sized> SelectableCapture<T> {
    fn new(capture: Capture<T>) -> Result<Self, Error> {
        let fd = unsafe { raw::pcap_get_selectable_fd(capture.as_ptr()) };
        if fd == -1 {
            return Err(Error::InvalidRawFd);
        }
        Ok(Self { inner: capture, fd })
    }
}

impl<T: Activated + ?Sized> AsRawFd for SelectableCapture<T> {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}
