use pcap::Capture;

fn main() {
    // get the default Device
    let device = pcap::Device::lookup().unwrap().unwrap();

    // Setup Capture
    let mut cap = pcap::Capture::from_device(device)
        .unwrap()
        .immediate_mode(true)
        .open()
        .unwrap();

    // remember linktype to create PCAP files later
    let linktype = cap.get_datalink();

    // Save each 30 packets into a new PCAP file
    let mut counter = 0;
    loop {
        let mut save_file = Capture::dead(linktype)
            .unwrap()
            .savefile(format!("dump_{}.pcap", counter))
            .unwrap();

        for _ in 0..30 {
            let packet = cap.next_packet().unwrap();
            save_file.write(&packet);
        }

        counter += 1;
    }
}
