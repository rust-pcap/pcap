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

#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() {
    let stream = start_new_stream().await;

    let fut = stream.for_each(move |s| {
        println!("{:?}", s);
        futures::future::ready(())
    });
    fut.await;
}
