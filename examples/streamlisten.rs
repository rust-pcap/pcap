extern crate pcap;
extern crate futures;
extern crate tokio_core;

use pcap::{Capture, Packet, Error, Device};
use pcap::tokio::PacketCodec;
use tokio_core::reactor::Core;
use futures::stream::Stream;

pub struct SimpleDumpCodec;

impl PacketCodec for SimpleDumpCodec{
    type Type = String;

    fn decode<'p>(&mut self, packet: Packet<'p>) -> Result<Self::Type, Error> {
        Ok(format!("{:?}", packet))

    }
}

fn ma1n() -> Result<(),Error> {
    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let cap = Capture::from_device(Device::lookup()?)?.open()?.setnonblock()?;
    let s = cap.stream(&handle, SimpleDumpCodec{})?;
    let done = s.for_each(move |s| {
        println!("{:?}", s);
        Ok(())
    });
    core.run(done).unwrap();
    Ok(())
}

fn main() {
    match ma1n() {
        Ok(()) => (),
        Err(e) => println!("{:?}", e),
    }
}
