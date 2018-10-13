extern crate pcap;
extern crate futures;
extern crate tokio;

use pcap::{Capture, Packet, Error, Device};
use pcap::stream::PacketCodec;
use tokio::reactor::Handle;
use tokio::runtime::Runtime;
use futures::future;
use futures::stream::Stream;

pub struct SimpleDumpCodec;

impl PacketCodec for SimpleDumpCodec{
    type Type = String;

    fn decode<'p>(&mut self, packet: Packet<'p>) -> Result<Self::Type, Error> {
        Ok(format!("{:?}", packet))

    }
}

fn ma1n() -> Result<(),Error> {
    let mut rt = Runtime::new().unwrap();
    let cap = Capture::from_device(Device::lookup()?)?.open()?.setnonblock()?;
    let fut = future::lazy(move || {
        let handle = Handle::current();
        let s = cap.stream(&handle, SimpleDumpCodec{}).unwrap();
        s.for_each(move |s| {
            println!("{:?}", s);
            Ok(())
        })
    });
    rt.block_on(fut).unwrap();
    Ok(())
}

fn main() {
    match ma1n() {
        Ok(()) => (),
        Err(e) => println!("{:?}", e),
    }
}
