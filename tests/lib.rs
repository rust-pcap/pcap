extern crate pcap;

use pcap::{Offline, Capture};
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
