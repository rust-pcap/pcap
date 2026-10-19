//! Example of using streams for a UDP echo server on port 80.
//!
//! A reply is the request with its source and destination swapped in the Ethernet, IPv4 and UDP
//! headers, which leaves both checksums valid. The filter turns away replies, which come from
//! port 80, so the server never echoes one, even where the capture also sees what it sends, and
//! requests to a broadcast or multicast address, which cannot be the source of a reply.
use futures::StreamExt;
use pcap::{Active, Capture, Device, Error, Linktype, Packet, PacketCodec, PacketStream};
use std::error;

// Simple codec that returns owned copies, since the result may not
// reference the input packet.
pub struct BoxCodec;

impl PacketCodec for BoxCodec {
    type Item = Box<[u8]>;

    fn decode(&mut self, packet: Packet) -> Self::Item {
        packet.data.into()
    }
}

fn new_stream(device: Device) -> Result<PacketStream<Active, BoxCodec>, Error> {
    // get the default Device
    println!("Using device {}", device.name);

    let mut cap = Capture::from_device(device)?
        .immediate_mode(true)
        .open()?
        .setnonblock()?;
    cap.filter(
        "ip and udp dst port 80 and not src port 80 and not ether multicast",
        true,
    )?;
    cap.stream(BoxCodec)
}

fn swap_endpoints(frame: &mut [u8]) {
    let (dst, src) = frame.split_at_mut(6);
    dst.swap_with_slice(&mut src[..6]);
    let ip = &mut frame[14..];
    let (src, dst) = ip[12..20].split_at_mut(4);
    src.swap_with_slice(dst);
    let udp = usize::from(ip[0] & 0x0f) * 4;
    let (src, dst) = ip[udp..udp + 4].split_at_mut(2);
    src.swap_with_slice(dst);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn error::Error>> {
    let device = Device::lookup()?.ok_or("no device available")?;
    let mut stream = new_stream(device)?;
    if stream.capture_mut().get_datalink() != Linktype::ETHERNET {
        return Err("the device does not use Ethernet headers".into());
    }

    loop {
        // Here in the event loop we may await a bunch of other
        // futures too, using the select! macro from tokio.
        let mut data = stream.next().await.unwrap()?;
        swap_endpoints(&mut data);
        // A non-blocking capture reports a full transmit queue as an error.
        if let Err(e) = stream.capture_mut().sendpacket(data) {
            eprintln!("reply dropped: {e}");
        }
    }
}
