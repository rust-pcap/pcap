use futures::StreamExt;
use pcap::stream::{PacketCodec, PacketStream};
use pcap::{Active, Capture, Device, Error, Packet};

pub struct SimpleDumpCodec;

impl PacketCodec for SimpleDumpCodec {
    type Type = String;

    fn decode(&mut self, packet: Packet) -> Result<Self::Type, Error> {
        Ok(format!("{:?}", packet))
    }
}

async fn start_new_stream() -> PacketStream<Active, SimpleDumpCodec> {
    match new_stream() {
        Ok(stream) => stream,
        Err(e) => {
            println!("{:?}", e);
            std::process::exit(1);
        }
    }
}

fn new_stream() -> Result<PacketStream<Active, SimpleDumpCodec>, Error> {
    // get the default Device
    let device = Device::lookup()?;
    println!("Using device {}", device.name);

    let cap = Capture::from_device(device)?
        .immediate_mode(true)
        .open()?
        .setnonblock()?;
    cap.stream(SimpleDumpCodec {})
}

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();

    let stream = rt.block_on(start_new_stream());

    let fut = stream.for_each(move |s| {
        println!("{:?}", s);
        futures::future::ready(())
    });
    rt.block_on(fut);
}
