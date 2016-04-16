extern crate pcap;
extern crate libc;

use pcap::{Active, Activated, Offline, Capture, Packet, PacketHeader};
use std::env;
use std::io::Write;
use std::fs;
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

#[test]
#[cfg(not(windows))]
fn capture_dead_savememory() {
	let p1_header = PacketHeader {
		ts: libc::timeval {
			tv_sec: 1460408319,
			tv_usec: 1234,
		},
		caplen: 1,
		len: 1,
	};
	let p1_data = vec![1u8];

	let p2_header = PacketHeader {
		ts: libc::timeval {
			tv_sec: 1460408320,
			tv_usec: 4321,
		},
		caplen: 1,
		len: 1,
	};
	let p2_data = vec![2u8];

	let mut packets = vec![];
	packets.push(Packet { header: &p1_header, data: &p1_data });
	packets.push(Packet { header: &p2_header, data: &p2_data });

	let mut tmp_file = env::temp_dir();
	tmp_file.push("pcap_dead_savememory_test.pcap");

	{
		// Scope for dead capture
		let dead_cap = pcap::Capture::dead(pcap::Linktype(1)).unwrap();
		let mut dead_save = dead_cap.savememory().unwrap();
		for packet in &packets {
			dead_save.write(&packet);
		}
		let contents = dead_save.dump().unwrap();

		let mut file = fs::File::create(&tmp_file).unwrap();
		file.write_all(&contents).unwrap();
	}

	{
		// Scope for offline capture
		let mut offline_cap = pcap::Capture::from_file(&tmp_file).unwrap();
		let mut idx = 0;
		while let Ok(packet) = offline_cap.next() {
			let orig_packet = &packets[idx];
			assert_eq!(orig_packet.header.ts.tv_sec, packet.header.ts.tv_sec);
			assert_eq!(orig_packet.header.ts.tv_usec, packet.header.ts.tv_usec);
			assert_eq!(orig_packet.header.caplen, packet.header.caplen);
			assert_eq!(orig_packet.header.len, packet.header.len);
			assert_eq!(orig_packet.data, packet.data);

			idx += 1;
		}
	}

	fs::remove_file(&tmp_file).unwrap();
}

#[test]
fn capture_dead_savefile() {
	let p1_header = PacketHeader {
		ts: libc::timeval {
			tv_sec: 1460408319,
			tv_usec: 1234,
		},
		caplen: 1,
		len: 1,
	};
	let p1_data = vec![1u8];

	let p2_header = PacketHeader {
		ts: libc::timeval {
			tv_sec: 1460408320,
			tv_usec: 4321,
		},
		caplen: 1,
		len: 1,
	};
	let p2_data = vec![2u8];

	let mut packets = vec![];
	packets.push(Packet { header: &p1_header, data: &p1_data });
	packets.push(Packet { header: &p2_header, data: &p2_data });

	let mut tmp_file = env::temp_dir();
	tmp_file.push("pcap_dead_savefile_test.pcap");

	{
		// Scope for dead capture
		let dead_cap = pcap::Capture::dead(pcap::Linktype(1)).unwrap();
		let mut dead_save = dead_cap.savefile(&tmp_file).unwrap();
		for packet in &packets {
			dead_save.write(&packet);
		}
	}

	{
		// Scope for offline capture
		let mut offline_cap = pcap::Capture::from_file(&tmp_file).unwrap();
		let mut idx = 0;
		while let Ok(packet) = offline_cap.next() {
			let orig_packet = &packets[idx];
			assert_eq!(orig_packet.header.ts.tv_sec, packet.header.ts.tv_sec);
			assert_eq!(orig_packet.header.ts.tv_usec, packet.header.ts.tv_usec);
			assert_eq!(orig_packet.header.caplen, packet.header.caplen);
			assert_eq!(orig_packet.header.len, packet.header.len);
			assert_eq!(orig_packet.data, packet.data);

			idx += 1;
		}
	}

	fs::remove_file(&tmp_file).unwrap();
}
