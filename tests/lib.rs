extern crate pcap;
extern crate libc;

use pcap::{Active, Activated, Offline, Capture, Packet, PacketHeader, Linktype};
use std::env;
use std::fs;
use std::ops::Add;
use std::path::Path;

#[test]
fn read_packet_with_full_data() {
    let mut capture = capture_from_test_file("packet_snaplen_65535.pcap");
    assert_eq!(capture.next().unwrap().len(), 98);
}

#[test]
fn read_packet_with_truncated_data() {
    let mut capture = capture_from_test_file("packet_snaplen_20.pcap");
    assert_eq!(capture.next().unwrap().len(), 20);
}

fn capture_from_test_file(file_name: &str) -> Capture<Offline> {
    let path = Path::new("tests/data/").join(file_name);
    Capture::from_file(path).unwrap()
}


#[test]
fn unify_activated() {
	  #![allow(dead_code)]
	  fn test1() -> Capture<Active> {
		    loop{}
	  }

	  fn test2() -> Capture<Offline> {
		    loop{}
	  }

	  fn maybe(a: bool) -> Capture<Activated> {
		    if a {
			      test1().into()
		    } else {
			      test2().into()
		    }
	  }

	  fn also_maybe(a: &mut Capture<Activated>) {
		    a.filter("whatever filter string, this won't be run anyway").unwrap();
	  }
}

#[derive(Clone)]
pub struct Packets {
    headers: Vec<PacketHeader>,
    data: Vec<Vec<u8>>,
}

impl Packets {
    pub fn new() -> Packets {
        Packets { headers: vec![], data: vec![] }
    }

    pub fn push(&mut self, tv_sec: libc::time_t, tv_usec: libc::suseconds_t,
                caplen: u32, len: u32, data: &[u8])
    {
        self.headers.push(PacketHeader {
            ts: libc::timeval { tv_sec: tv_sec, tv_usec: tv_usec },
            caplen: caplen,
            len: len,
        });
        self.data.push(data.to_vec());
    }

    pub fn foreach<F: FnMut(&Packet)>(&self, mut f: F) {
        for (header, data) in self.headers.iter().zip(self.data.iter()) {
            let packet = Packet { header: header, data: &data };
            f(&packet);
        }
    }

    pub fn verify<T: Activated + ?Sized>(&self, cap: &mut Capture<T>) {
        for (header, data) in self.headers.iter().zip(self.data.iter()) {
            assert_eq!(cap.next().unwrap(), Packet { header: header, data: &data });
        }
        assert!(cap.next().is_err());
    }
}

impl<'a> Add for &'a Packets {
    type Output = Packets;

    fn add(self, rhs: &'a Packets) -> Packets {
        let mut packets = self.clone();
        packets.headers.extend(rhs.headers.iter());
        packets.data.extend(rhs.data.iter().cloned());
        packets
    }
}

#[test]
fn capture_dead_savefile() {
    let mut packets = Packets::new();
    packets.push(1460408319, 1234, 1, 1, &[1]);
    packets.push(1460408320, 4321, 1, 1, &[2]);

	  let mut tmp_file = env::temp_dir();
	  tmp_file.push("pcap_dead_savefile_test.pcap");

    let cap = Capture::dead(Linktype(1)).unwrap();
    let mut save = cap.savefile(&tmp_file).unwrap();
    packets.foreach(|p| save.write(p));
    drop(save);

    let mut cap = Capture::from_file(&tmp_file).unwrap();
    packets.verify(&mut cap);

	  fs::remove_file(&tmp_file).unwrap();
}

#[test]
#[cfg(feature = "pcap-savefile-append")]
fn capture_dead_savefile_append() {
    let mut packets1 = Packets::new();
    packets1.push(1460408319, 1234, 1, 1, &[1]);
    packets1.push(1460408320, 4321, 1, 1, &[2]);
    let mut packets2 = Packets::new();
    packets2.push(1460408321, 2345, 1, 1, &[3]);
    packets2.push(1460408322, 5432, 1, 1, &[4]);
    let packets = &packets1 + &packets2;

	  let mut tmp_file = env::temp_dir();
	  tmp_file.push("pcap_dead_savefile_append_test.pcap");

    let cap = Capture::dead(Linktype(1)).unwrap();
    let mut save = cap.savefile(&tmp_file).unwrap();
    packets1.foreach(|p| save.write(p));
    drop(save);

    let cap = Capture::dead(Linktype(1)).unwrap();
    let mut save = cap.savefile_append(&tmp_file).unwrap();
    packets2.foreach(|p| save.write(p));
    drop(save);

    let mut cap = Capture::from_file(&tmp_file).unwrap();
    packets.verify(&mut cap);

	  fs::remove_file(&tmp_file).unwrap();
}
