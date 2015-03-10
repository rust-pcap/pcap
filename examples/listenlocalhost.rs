extern crate pcap;

fn main() {
    // listen on the device named "any", which is only available on Linux. On Windows you may need to
    // use Devices::list_all() and listen to each or the specific ones you need
    let mut d: pcap::Capture = pcap::Device::new("any").open().unwrap();

    // filter out all packets that don't have 127.0.0.1 as a source or destination.
    d.filter("host 127.0.0.1").unwrap();

    for packet in d.listen() {
        println!("got packet! {:?}", &*packet); // `Packet` can be Deref'd into the actual raw packet slice
    }
}