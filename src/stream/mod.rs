#[cfg(unix)]
pub mod unix;
#[cfg(unix)]
pub use unix::PacketStream;

#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
pub use windows::PacketStream;

use crate::{
    Error,
    capture::{Activated, Capture},
    codec::PacketCodec,
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

#[cfg(test)]
mod tests {
    use crate::{
        capture::{Active, testmod::test_capture},
        codec::testmod::Codec,
        raw::testmod::{RAWMTX, as_pcap_t},
    };

    use super::PacketStream;

    #[test]
    fn test_stream_error() {
        let _m = RAWMTX.lock();

        let mut dummy: isize = 777;
        let pcap = as_pcap_t(&mut dummy);

        let test_capture = test_capture::<Active>(pcap);
        let capture = test_capture.capture;
        assert!(!capture.is_nonblock());

        let result = capture.stream(Codec);
        assert!(result.is_err());
    }

    // On Windows the stream drives an event HANDLE, which is a raw pointer and so not Send on
    // its own. Callers hand the stream to an executor, so make sure it stays Send.
    #[test]
    fn test_stream_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<PacketStream<Active, Codec>>();
    }
}
