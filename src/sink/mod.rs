//! Support for asynchronous packet transmission.
//!
//! See [`Capture::sink`](super::Capture::sink).
use std::io;
use std::marker::Unpin;
use std::pin::Pin;
use std::task::{self, Poll};

use futures::ready;
use tokio::io::unix::AsyncFd;

use crate::{
    capture::{selectable::SelectableCapture, Active, Capture},
    Error,
};

impl Capture<Active> {
    /// Returns this capture as a [`futures::Sink`] for sending packets.
    ///
    /// # Errors
    ///
    /// If this capture is set to be blocking, or if the network device
    /// does not support `select()`, an error will be returned.
    pub fn sink<C>(self) -> Result<PacketSink<C>, Error> {
        if !self.is_nonblock() {
            return Err(Error::NonNonBlock);
        }
        PacketSink::new(self)
    }
}

/// Implement Sink for async use of pcap
pub struct PacketSink<C> {
    inner: AsyncFd<SelectableCapture<Active>>,
    packet: Option<C>,
}

impl<C> PacketSink<C> {
    pub(crate) fn new(capture: Capture<Active>) -> Result<Self, Error> {
        let capture = SelectableCapture::new(capture)?;

        Ok(PacketSink {
            inner: AsyncFd::with_interest(capture, tokio::io::Interest::WRITABLE)?,
            packet: None,
        })
    }

    /// Returns a mutable reference to the inner [`Capture`].
    ///
    /// The caller must ensure the capture will not be set to be blocking.
    pub fn capture_mut(&mut self) -> &mut Capture<Active> {
        self.inner.get_mut().get_inner_mut()
    }
}

impl<C> Unpin for PacketSink<C> {}

impl<C: AsRef<[u8]>> futures::Sink<C> for PacketSink<C> {
    type Error = Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: C) -> Result<(), Self::Error> {
        let sink = Pin::into_inner(self);
        debug_assert!(sink.packet.is_none());
        sink.packet = Some(item);
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let sink = Pin::into_inner(self);
        let packet_storage = &mut sink.packet;

        loop {
            let mut guard = ready!(sink.inner.poll_write_ready_mut(cx))?;

            if let Some(packet) = packet_storage.take() {
                match guard.try_io(
                    |inner| {
                        match inner.get_mut().get_inner_mut().sendpacket(packet.as_ref()) {
                            Ok(()) => Ok(Ok(())),
                            Err(e) => {
                                *packet_storage = Some(packet);
                                if e == Error::TimeoutExpired {
                                    Err(io::Error::new(io::ErrorKind::WouldBlock, e))
                                } else {
                                    Ok(Err(e))
                                }
                            }
                        }
                    }
                ) {
                    Ok(result) => {
                        return Poll::Ready(result?);
                    }
                    Err(_would_block) => continue,
                }
            } else {
                return Poll::Ready(Ok(()))
            }
        }
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.poll_flush(cx)
    }
}
