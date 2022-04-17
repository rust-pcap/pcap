//! Support for asynchronous packet iteration.
//!
//! See [`Capture::stream`](super::Capture::stream).
use super::Activated;
use super::Capture;
use super::Error;
use super::Packet;
use super::SelectableCapture;
use futures::ready;
use std::io;
use std::marker::Unpin;
use std::pin::Pin;
use std::task::{self, Poll};
use tokio::io::unix::AsyncFd;

pub trait PacketCodec {
    type Type;
    fn decode(&mut self, packet: Packet) -> Result<Self::Type, Error>;
}

pub struct PacketStream<T: Activated + ?Sized, C> {
    inner: AsyncFd<SelectableCapture<T>>,
    pub codec: C,
}

impl<T: Activated + ?Sized, C> PacketStream<T, C> {
    pub(crate) fn new(capture: SelectableCapture<T>, codec: C) -> Result<Self, Error> {
        Ok(PacketStream {
            inner: AsyncFd::with_interest(capture, tokio::io::Interest::READABLE)?,
            codec,
        })
    }

    /// Returns a mutable reference to the inner [`Capture`].
    ///
    /// The caller must ensure the capture will not be set to be
    /// blocking.
    pub fn inner_mut(&mut self) -> &mut Capture<T> {
        &mut self.inner.get_mut().inner
    }
}

impl<T: Activated + ?Sized, C> Unpin for PacketStream<T, C> {}

impl<T: Activated + ?Sized, C: PacketCodec> futures::Stream for PacketStream<T, C> {
    type Item = Result<C::Type, Error>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut task::Context) -> Poll<Option<Self::Item>> {
        let stream = Pin::into_inner(self);
        let codec = &mut stream.codec;
        loop {
            let mut guard = ready!(stream.inner.poll_read_ready_mut(cx))?;
            match guard.try_io(|inner| match inner.get_mut().inner.next() {
                Ok(p) => Ok(Ok(codec.decode(p))),
                Err(e @ Error::TimeoutExpired) => Err(io::Error::new(io::ErrorKind::WouldBlock, e)),
                Err(e) => Ok(Err(e)),
            }) {
                Ok(result) => {
                    let frame_result = result.unwrap()?;
                    return Poll::Ready(Some(frame_result));
                }
                Err(_would_block) => continue,
            }
        }
    }
}
