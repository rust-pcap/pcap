use mio::{Ready, Poll, PollOpt, Token};
use mio::event::Evented;
use mio::unix::EventedFd;
use std::io;
use std::marker::Unpin;
#[cfg(not(windows))]
use std::os::unix::io::RawFd;
use std::pin::Pin;
use super::Activated;
use super::Packet;
use super::Error;
use super::State;
use super::Capture;
use tokio;
use futures;

pub struct SelectableFd {
    fd: RawFd
}

impl Evented for SelectableFd {
    fn register(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt)
                -> io::Result<()>
    {
        EventedFd(&self.fd).register(poll, token, interest, opts)
    }

    fn reregister(&self, poll: &Poll, token: Token, interest: Ready, opts: PollOpt)
                  -> io::Result<()>
    {
        EventedFd(&self.fd).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &Poll) -> io::Result<()> {
        EventedFd(&self.fd).deregister(poll)
    }
}

pub trait PacketCodec {
    type Type;
    fn decode<'a>(&mut self, packet: Packet<'a>) -> Result<Self::Type, Error>;
}

pub struct PacketStream<T: State + ? Sized, C> {
    cap: Capture<T>,
    fd: tokio::io::PollEvented<SelectableFd>,
    codec: C,
}

impl<T: Activated + ? Sized, C: PacketCodec> PacketStream<T, C> {
    pub fn new(cap: Capture<T>, fd: RawFd, codec: C) -> Result<PacketStream<T, C>, Error> {
        Ok(PacketStream { cap: cap, fd: tokio::io::PollEvented::new(SelectableFd { fd: fd })?, codec: codec })
    }
}

impl<'a, T: Activated + ? Sized + Unpin, C: PacketCodec + Unpin> futures::Stream for PacketStream<T, C> {
    type Item = Result<C::Type, Error>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut core::task::Context) -> futures::task::Poll<Option<Self::Item>> {
        let stream = Pin::into_inner(self);
        let p = match stream.cap.next_noblock(cx, &mut stream.fd) {
            Ok(t) => t,
            Err(Error::IoError(ref e)) if *e == ::std::io::ErrorKind::WouldBlock => {
                return futures::task::Poll::Pending;
            }
            Err(e) => return futures::task::Poll::Ready(Some(Err(e.into()))),
        };
        let frame_result = stream.codec.decode(p);
        futures::task::Poll::Ready(Some(frame_result))
    }
}
