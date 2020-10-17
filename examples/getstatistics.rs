fn main() {
    // get the default Device
    let device = pcap::Device::lookup().unwrap();
    println!("Using device {}", device.name);

    // Setup Capture
    let mut cap = pcap::Capture::from_device(device)
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    // get 10 packets
    for _ in 0..10 {
        cap.next().ok();
    }
    let stats = cap.stats().unwrap();
    println!(
        "Received: {}, dropped: {}, if_dropped: {}",
        stats.received, stats.dropped, stats.if_dropped
    );
}
