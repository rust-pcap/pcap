fn main() {
    // get the default Device
    let mut cap = pcap::Device::lookup().unwrap().open().unwrap();

    // get 10 packets
    for _ in 0..10 {
      cap.next().ok();
    }
    let stats = cap.stats().unwrap();
    println!("Received: {}, dropped: {}, if_dropped: {}", stats.received, stats.dropped, stats.if_dropped);
}
