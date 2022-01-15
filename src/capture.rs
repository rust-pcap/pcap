use crate::Error;
use crate::State;
use crate::{raw, Capture, PacketHeader};
use libc::c_int;
use libc::c_uchar;

/// The type for the function to pass into pcap_loop
pub type HandlerFunc = fn(&PacketHeader, pkt_data: &[u8]) -> ();

/// An internal function to convert the callback capture into rust safe function,
/// #Safety
/// using mem::transmute here is fine since `HandlerFunc` **Should** be the equivalent of
/// pcap_handler (removing the extern and unsafe keyword, need to check if removing them have
/// unidentified behavior although we are converting from and into the same type)
unsafe extern "C" fn capturer(
    params: *mut c_uchar,
    raw_header: *const raw::pcap_pkthdr,
    raw_pkt_data: *const c_uchar,
) {
    let callback: HandlerFunc = std::mem::transmute(params);
    let header = *(raw_header as *const PacketHeader);
    // let header = &*(&*raw_header as *const raw::pcap_pkthdr as *const PacketHeader);
    let pkt_data = std::slice::from_raw_parts(raw_pkt_data, header.caplen as _);

    callback(&header, pkt_data);
}

///Processes packets from a live capture or ``savefile`` until max packets are processed,
///or the end of the ``savefile`` is reached when reading from a ``savefile``
/// **Note:** pcap_loop is blocking so `setnonblock` will have no effect
pub fn pcap_loop<T: State>(
    capture: Capture<T>,
    max: Option<usize>,
    handler: HandlerFunc,
) -> Result<(), Error> {
    let result = unsafe {
        raw::pcap_loop(
            *capture.handle,
            max.map_or(0, |c| c) as c_int,
            Some(capturer),
            handler as *mut _,
        )
    };

    match result {
        0 => Ok(()),
        -2 => Err(Error::NoMorePackets),
        _ => capture.check_err(false),
    }
}
