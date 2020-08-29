fn main() {
    // get the default Device
    let mut cap = pcap::Device::lookup().unwrap().open().unwrap();

    // get a packet and print its bytes
    println!("{:?}", cap.next());
}
