extern crate pcap;

fn main() {
	// list all of the devices pcap tells us are available
	for device in pcap::Devices::list_all().unwrap() {
		println!("Found device! {:?}", device);

		// now you can .open() on this device to get a Capture if you want
	}
}