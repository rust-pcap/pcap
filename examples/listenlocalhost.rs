fn main() {
    // listen on the device named "any", which is only available on Linux. This is only for
    // demonstration purposes.
    let mut cap = pcap::Capture::from_device("any")
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    // filter out all packets that don't have 127.0.0.1 as a source or destination.
    let mut filter = cap.compile_filter("host 127.0.0.1", true).unwrap();
    cap.filter(&mut filter).unwrap();

    while let Ok(packet) = cap.next() {
        println!("got packet! {:?}", packet);
    }
    pcap::pcap_loop(cap, Some(8), handler).unwrap();
}

fn handler(packet: pcap::Packet) {
    println!("Loop Got {:?}", packet)
}
