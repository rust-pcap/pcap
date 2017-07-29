extern crate pcap;
extern crate mio;
extern crate futures;
extern crate tokio_core;

use std::io;
use futures::stream::Stream;
use futures::{Async, Poll};
use tokio_core::reactor::{Core, Handle, PollEvented};
use mio::unix::EventedFd;
use std::os::unix::io::RawFd;

pub struct OwnedPacket {
    header: pcap::PacketHeader,
    data: Vec<u8>,
}

impl<'a> Into<OwnedPacket> for pcap::Packet<'a> {
    fn into(self) -> OwnedPacket {
        OwnedPacket {
            header: self.header.clone(),
            data: self.data.to_vec(),
        }
    }
}

pub struct AsyncPcap<'a> {
    inner: &'a mut pcap::Capture<pcap::Active>,
    io: PollEvented<EventedFd<'a>>,
}

impl<'a> AsyncPcap<'a> {
    pub fn init(
        device: &'a mut pcap::Capture<pcap::Active>,
        raw_fd: &'a RawFd,
        handle: &Handle,
    ) -> io::Result<AsyncPcap<'a>> {
        let poll_evented = PollEvented::new(EventedFd(&raw_fd), handle)?;
        Ok(AsyncPcap {
            inner: device,
            io: poll_evented,
        })
    }
}

impl<'a> Stream for AsyncPcap<'a> {
    type Item = OwnedPacket;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self.io.poll_read() {
            Async::NotReady => Ok(Async::NotReady),
            Async::Ready(_) => match self.inner.next() {
                Ok(p) => Ok(Async::Ready(Some(p.into()))),
                Err(_) => {
                    self.io.need_read();
                    Ok(Async::NotReady)
                }
            },
        }
    }
}

fn main() {
    /// Create a reactor using tokio
    let mut event_loop = Core::new().unwrap();
    let handle = event_loop.handle();

    // get the default Device and make it non blocking
    // let mut cap = pcap::Device::lookup().unwrap().open().unwrap();
    let dev: pcap::Device = "wlp58s0".into();
    let mut capture = dev.open().unwrap();
    capture.setnonblock(true).unwrap();

    // get the raw fd from the capture device
    let fd = &capture.get_selectable_fd().unwrap();

    // create a async stream for received packets
    let async_pcap = AsyncPcap::init(&mut capture, fd, &handle).unwrap();

    // read 10 packets and quit with an Error
    let mut i: u8 = 0;
    let listener = async_pcap.for_each(|p| {
        println!("Packet {:?} - {}", p.header, p.data[0]);
        i += 1;
        if i > 10 {
            Err(io::Error::new(io::ErrorKind::Interrupted, "reached 10"))
        } else {
            Ok(())
        }
    });

    // run the packet listener and ignore the resulting Result
    let _ = event_loop.run(listener);
}
