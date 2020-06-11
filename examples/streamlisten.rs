extern crate futures;
extern crate pcap;
extern crate tokio;

use futures::StreamExt;
use pcap::stream::{PacketCodec, PacketStream};
use pcap::{Active, Capture, Device, Error, Packet};

pub struct SimpleDumpCodec;

impl PacketCodec for SimpleDumpCodec {
    type Type = String;

    fn decode<'p>(&mut self, packet: Packet<'p>) -> Result<Self::Type, Error> {
        Ok(format!("{:?}", packet))
    }
}

fn new_stream() -> Result<PacketStream<Active, SimpleDumpCodec>, Error> {
    let cap = Capture::from_device(Device::lookup()?)?
        .open()?
        .setnonblock()?;
    cap.stream(SimpleDumpCodec {})
}

fn main() {
    let mut rt = tokio::runtime::Builder::new()
        .enable_io()
        .basic_scheduler()
        .build()
        .unwrap();

    let stream = rt.enter(|| match new_stream() {
        Ok(stream) => stream,
        Err(e) => {
            println!("{:?}", e);
            std::process::exit(1);
        }
    });

    let fut = stream.for_each(move |s| {
        println!("{:?}", s);
        futures::future::ready(())
    });
    rt.block_on(fut);
}
