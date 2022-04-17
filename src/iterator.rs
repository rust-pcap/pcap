use crate::Activated;
use crate::Capture;
use crate::Error;
use crate::PacketCodec;

/// Implement an Iterator of Packet
pub struct PacketIter<S: Activated + ?Sized, C> {
    capture: Capture<S>,
    codec: C,
}

impl<S: Activated + ?Sized, C> PacketIter<S, C> {
    pub(crate) fn new(capture: Capture<S>, codec: C) -> Self {
        Self { capture, codec }
    }

    pub fn capture_mut(&mut self) -> &mut Capture<S> {
        &mut self.capture
    }
}

impl<S: Activated + ?Sized, C> From<PacketIter<S, C>> for (Capture<S>, C) {
    fn from(iter: PacketIter<S, C>) -> Self {
        (iter.capture, iter.codec)
    }
}

impl<S: Activated + ?Sized, C: PacketCodec> Iterator for PacketIter<S, C> {
    type Item = Result<C::Item, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.capture.next() {
            Ok(packet) => Some(Ok(self.codec.decode(packet))),
            Err(Error::NoMorePackets) => None,
            Err(e) => Some(Err(e)),
        }
    }
}
