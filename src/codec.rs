use crate::Packet;

/// This trait is used to implement Stream and Iterator feature.
/// This is almost like `map()`.
///
// This is needed cause we don't have GaTs
// Once GaTs are stable we could use them to implement better Iterator
pub trait PacketCodec {
    type Item;

    fn decode(&mut self, packet: Packet<'_>) -> Self::Item;
}
