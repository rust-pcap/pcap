extern crate pcap;

fn main() {
    // get the default Device
    let default = pcap::Device::lookup().unwrap();

    // open a capture handle from it
    let mut cap = pcap::Capture::from_device(default).unwrap();

    // get a packet and print its bytes
    println!("{:?}", cap.next());
}
