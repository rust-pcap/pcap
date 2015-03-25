extern crate pcap;

fn main() {
    // listen on the device named "any", which is only available on Linux. On Windows you may need to
    // use Devices::list_all() and listen to each or the specific ones you need
    let mut cap = pcap::Capture::new("any").unwrap();

    // filter out all packets that don't have 127.0.0.1 as a source or destination.
    cap.filter("host 127.0.0.1").unwrap();

    while let Some(packet) = cap.next() {
    	println!("got packet! {:?}", packet);
    }
}