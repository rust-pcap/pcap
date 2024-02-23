use crate::{
    capture::{Activated, Capture},
    codec::PacketCodec,
    Error,
};

/// Implement an Iterator of Packet
pub struct PacketIter<S: Activated + ?Sized, C> {
    capture: Capture<S>,
    codec: C,
}

impl<S: Activated + ?Sized, C> PacketIter<S, C> {
    pub(crate) fn new(capture: Capture<S>, codec: C) -> Self {
        Self { capture, codec }
    }

    /// Returns a mutable reference to the inner [`Capture`].
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
        match self.capture.next_packet() {
            Ok(packet) => Some(Ok(self.codec.decode(packet))),
            Err(Error::NoMorePackets) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(feature = "lending-iter")]
mod lending_iter {
    use crate::Activated;
    use crate::Capture;
    use crate::Error;
    use crate::Packet;
    use gat_std::iter::{IntoIterator, Iterator};

    pub struct PacketLendingIter<S: Activated + ?Sized> {
        capture: Capture<S>,
    }

    impl<S: Activated + ?Sized + 'static> IntoIterator for Capture<S> {
        type IntoIter = PacketLendingIter<S>;

        fn into_iter(self) -> Self::IntoIter {
            PacketLendingIter { capture: self }
        }
    }

    impl<S: Activated + ?Sized + 'static> Iterator for PacketLendingIter<S> {
        type Item<'a> = Result<Packet<'a>, Error>;

        fn next(&mut self) -> Option<Self::Item<'_>> {
            match self.capture.next_packet() {
                Ok(packet) => Some(Ok(packet)),
                Err(Error::NoMorePackets) => None,
                Err(e) => Some(Err(e)),
            }
        }
    }
}
