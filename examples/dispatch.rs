fn main() {
    // get the default Device
    let device = pcap::Device::lookup()
        .expect("device lookup failed")
        .expect("no device available");
    println!("Using device {}", device.name);

    // Setup Capture with a read timeout so dispatch returns even on a quiet interface
    let mut cap = pcap::Capture::from_device(device)
        .unwrap()
        .timeout(1000)
        .open()
        .unwrap();

    // Process packets in batches until we have seen 100 of them
    let mut count = 0;
    while count <= 100 {
        cap.dispatch(None, |packet| {
            println!("Got {:?}", packet.header);
            count += 1;
        })
        .unwrap();
    }
}
