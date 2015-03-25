extern crate pcap;

fn main() {
    // list all of the devices pcap tells us are available
    for device in pcap::Devices::list_all().unwrap() {
        println!("Found device! {:?}", device);

        // now you can .open() on this device to get a Capture if you want
        let mut cap = pcap::Capture::new(device).unwrap();

        // get a packet from this device
        {
        	let packet = cap.next();

        	println!("got a packet! {:?}", packet);
        }
    }
}