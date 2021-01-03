fn main() {
    // list all of the devices pcap tells us are available
    for device in pcap::Device::list().unwrap() {
        println!("Found device! {:?}", device);

        // now you can create a Capture with this Device if you want.
        // see example/easylisten.rs for how
    }
}
