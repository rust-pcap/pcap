#[cfg(unix)]
pub mod unix;
#[cfg(unix)]
pub use unix::PacketStream;

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub use windows::PacketStream;

use crate::{
    core::{
        capture::{Activated, Capture},
        codec::PacketCodec,
    },
    Error,
};

impl<T: Activated + ?Sized> Capture<T> {
    /// Returns this capture as a [`futures::Stream`] of packets.
    ///
    /// # Errors
    ///
    /// If this capture is set to be blocking, or if the network device
    /// does not support `select()`, an error will be returned.
    pub fn stream<C: PacketCodec>(self, codec: C) -> Result<PacketStream<T, C>, Error> {
        if !self.is_nonblock() {
            return Err(Error::NonNonBlock);
        }
        PacketStream::new(self, codec)
    }
}
