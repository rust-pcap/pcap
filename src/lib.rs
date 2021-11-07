//! pcap is a packet capture library available on Linux, Windows and Mac. This
//! crate supports creating and configuring capture contexts, sniffing packets,
//! sending packets to interfaces, listing devices, and recording packet captures
//! to pcap-format dump files.
//!
//! # Capturing packets
//! The easiest way to open an active capture handle and begin sniffing is to
//! use `.open()` on a `Device`. You can obtain the "default" device using
//! `Device::lookup()`, or you can obtain the device(s) you need via `Device::list()`.
//!
//! ```ignore
//! use pcap::Device;
//!
//! fn main() {
//!     let mut cap = Device::lookup().unwrap().open().unwrap();
//!
//!     while let Ok(packet) = cap.next() {
//!         println!("received packet! {:?}", packet);
//!     }
//! }
//! ```
//!
//! `Capture`'s `.next()` will produce a `Packet` which can be dereferenced to access the
//! `&[u8]` packet contents.
//!
//! # Custom configuration
//!
//! You may want to configure the `timeout`, `snaplen` or other parameters for the capture
//! handle. In this case, use `Capture::from_device()` to obtain a `Capture<Inactive>`, and
//! proceed to configure the capture handle. When you're finished, run `.open()` on it to
//! turn it into a `Capture<Active>`.
//!
//! ```ignore
//! use pcap::{Device,Capture};
//!
//! fn main() {
//!     let main_device = Device::lookup().unwrap();
//!     let mut cap = Capture::from_device(main_device).unwrap()
//!                       .promisc(true)
//!                       .snaplen(5000)
//!                       .open().unwrap();
//!
//!     while let Ok(packet) = cap.next() {
//!         println!("received packet! {:?}", packet);
//!     }
//! }
//! ```

use unique::Unique;

#[cfg(feature = "capture-stream")]
use core::task::Poll::Ready;
use std::borrow::Borrow;
use std::ffi::{self, CStr, CString};
use std::fmt;
#[cfg(feature = "capture-stream")]
use std::io;
use std::marker::PhantomData;
use std::mem;
use std::net::IpAddr;
use std::ops::Deref;
#[cfg(not(windows))]
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::ptr;
use std::slice;

use self::Error::*;

#[cfg(target_os = "windows")]
use widestring::WideCString;

#[cfg(target_os = "windows")]
use winapi::shared::{
    ws2def::{AF_INET, AF_INET6, SOCKADDR_IN},
    ws2ipdef::SOCKADDR_IN6,
};

mod raw;
#[cfg(feature = "capture-stream")]
pub mod stream;
mod unique;

/// An error received from pcap
#[derive(Debug, PartialEq)]
pub enum Error {
    /// The underlying library returned invalid UTF-8
    MalformedError(std::str::Utf8Error),
    /// The underlying library returned a null string
    InvalidString,
    /// The unerlying library returned an error
    PcapError(String),
    /// The linktype was invalid or unknown
    InvalidLinktype,
    /// The timeout expired while reading from a live capture
    TimeoutExpired,
    /// No more packets to read from the file
    NoMorePackets,
    /// Must be in non-blocking mode to function
    NonNonBlock,
    /// There is not sufficent memory to create a dead capture
    InsufficientMemory,
    /// An invalid input string (internal null)
    InvalidInputString,
    /// An IO error occurred
    IoError(std::io::ErrorKind),
    #[cfg(not(windows))]
    /// An invalid raw file descriptor was provided
    InvalidRawFd,
    /// Errno error
    ErrnoError(errno::Errno),
}

impl Error {
    unsafe fn new(ptr: *const libc::c_char) -> Error {
        match cstr_to_string(ptr) {
            Err(e) => e as Error,
            Ok(string) => PcapError(string.unwrap_or_default()),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MalformedError(ref e) => write!(f, "libpcap returned invalid UTF-8: {}", e),
            InvalidString => write!(f, "libpcap returned a null string"),
            PcapError(ref e) => write!(f, "libpcap error: {}", e),
            InvalidLinktype => write!(f, "invalid or unknown linktype"),
            TimeoutExpired => write!(f, "timeout expired while reading from a live capture"),
            NonNonBlock => write!(f, "must be in non-blocking mode to function"),
            NoMorePackets => write!(f, "no more packets to read from the file"),
            InsufficientMemory => write!(f, "insufficient memory"),
            InvalidInputString => write!(f, "invalid input string (internal null)"),
            IoError(ref e) => write!(f, "io error occurred: {:?}", e),
            #[cfg(not(windows))]
            InvalidRawFd => write!(f, "invalid raw file descriptor provided"),
            ErrnoError(ref e) => write!(f, "libpcap os errno: {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            MalformedError(..) => "libpcap returned invalid UTF-8",
            PcapError(..) => "libpcap FFI error",
            InvalidString => "libpcap returned a null string",
            InvalidLinktype => "invalid or unknown linktype",
            TimeoutExpired => "timeout expired while reading from a live capture",
            NonNonBlock => "must be in non-blocking mode to function",
            NoMorePackets => "no more packets to read from the file",
            InsufficientMemory => "insufficient memory",
            InvalidInputString => "invalid input string (internal null)",
            IoError(..) => "io error occurred",
            #[cfg(not(windows))]
            InvalidRawFd => "invalid raw file descriptor provided",
            ErrnoError(..) => "internal error, providing errno",
        }
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        match *self {
            MalformedError(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<ffi::NulError> for Error {
    fn from(_: ffi::NulError) -> Error {
        InvalidInputString
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(obj: std::str::Utf8Error) -> Error {
        MalformedError(obj)
    }
}

impl From<std::io::Error> for Error {
    fn from(obj: std::io::Error) -> Error {
        IoError(obj.kind())
    }
}

impl From<std::io::ErrorKind> for Error {
    fn from(obj: std::io::ErrorKind) -> Error {
        IoError(obj)
    }
}

#[derive(Debug, Clone)]
/// A network device name and (potentially) pcap's description of it.
pub struct Device {
    /// The name of the interface
    pub name: String,
    /// A textual description of the interface, if available
    pub desc: Option<String>,
    /// Addresses associated with this interface
    pub addresses: Vec<Address>,
}

impl Device {
    fn new(name: String, desc: Option<String>, addresses: Vec<Address>) -> Device {
        Device {
            name,
            desc,
            addresses,
        }
    }

    /// Opens a `Capture<Active>` on this device.
    pub fn open(self) -> Result<Capture<Active>, Error> {
        Capture::from_device(self)?.open()
    }

    /// Returns the default Device suitable for captures according to pcap_lookupdev,
    /// or an error from pcap.
    #[cfg(not(target_os = "windows"))]
    pub fn lookup() -> Result<Device, Error> {
        with_errbuf(|err| unsafe {
            cstr_to_string(raw::pcap_lookupdev(err))?
                .map(|name| Device::new(name, None, Vec::new()))
                .ok_or_else(|| Error::new(err))
        })
    }
    #[cfg(target_os = "windows")]
    pub fn lookup() -> Result<Device, Error> {
        with_errbuf(|err| unsafe {
            wstr_to_string(raw::pcap_lookupdev(err))?
                .map(|name| Device::new(name, None, Vec::new()))
                .ok_or_else(|| Error::new(err))
        })
    }

    /// Returns a vector of `Device`s known by pcap via pcap_findalldevs.
    pub fn list() -> Result<Vec<Device>, Error> {
        with_errbuf(|err| unsafe {
            let mut dev_buf: *mut raw::pcap_if_t = ptr::null_mut();
            if raw::pcap_findalldevs(&mut dev_buf, err) != 0 {
                return Err(Error::new(err));
            }
            let result = (|| {
                let mut devices = vec![];
                let mut cur = dev_buf;
                while !cur.is_null() {
                    let dev = &*cur;
                    devices.push(Device::new(
                        cstr_to_string(dev.name)?.ok_or(InvalidString)?,
                        cstr_to_string(dev.description)?,
                        Address::new_vec(dev.addresses),
                    ));
                    cur = dev.next;
                }
                Ok(devices)
            })();
            raw::pcap_freealldevs(dev_buf);
            result
        })
    }
}

impl From<&str> for Device {
    fn from(name: &str) -> Self {
        Device::new(name.into(), None, Vec::new())
    }
}

#[derive(Debug, Clone)]
/// Address information for an interface
pub struct Address {
    /// The address
    pub addr: IpAddr,
    /// Network mask for this address
    pub netmask: Option<IpAddr>,
    /// Broadcast address for this address
    pub broadcast_addr: Option<IpAddr>,
    /// P2P destination address for this address
    pub dst_addr: Option<IpAddr>,
}

impl Address {
    unsafe fn new_vec(mut ptr: *const raw::pcap_addr_t) -> Vec<Address> {
        let mut vec = Vec::new();
        while !ptr.is_null() {
            if let Some(addr) = Address::new(ptr) {
                vec.push(addr);
            }
            ptr = (*ptr).next;
        }
        vec
    }

    unsafe fn new(ptr: *const raw::pcap_addr_t) -> Option<Address> {
        Self::convert_sockaddr((*ptr).addr).map(|addr| Address {
            addr,
            netmask: Self::convert_sockaddr((*ptr).netmask),
            broadcast_addr: Self::convert_sockaddr((*ptr).broadaddr),
            dst_addr: Self::convert_sockaddr((*ptr).dstaddr),
        })
    }

    #[cfg(not(target_os = "windows"))]
    unsafe fn convert_sockaddr(ptr: *const libc::sockaddr) -> Option<IpAddr> {
        if ptr.is_null() {
            return None;
        }

        match (*ptr).sa_family as i32 {
            libc::AF_INET => {
                let ptr: *const libc::sockaddr_in = std::mem::transmute(ptr);
                Some(IpAddr::V4(u32::from_be((*ptr).sin_addr.s_addr).into()))
            }

            libc::AF_INET6 => {
                let ptr: *const libc::sockaddr_in6 = std::mem::transmute(ptr);
                Some(IpAddr::V6((*ptr).sin6_addr.s6_addr.into()))
            }

            _ => None,
        }
    }

    #[cfg(target_os = "windows")]
    unsafe fn convert_sockaddr(ptr: *const libc::sockaddr) -> Option<IpAddr> {
        if ptr.is_null() {
            return None;
        }

        match (*ptr).sa_family as i32 {
            AF_INET => {
                let ptr: *const SOCKADDR_IN = std::mem::transmute(ptr);
                let addr: [u8; 4] = std::mem::transmute(*(*ptr).sin_addr.S_un.S_addr());
                Some(IpAddr::from(addr))
            }
            AF_INET6 => {
                let ptr: *const SOCKADDR_IN6 = std::mem::transmute(ptr);
                let addr = *(*ptr).sin6_addr.u.Byte();
                Some(IpAddr::from(addr))
            }

            _ => None,
        }
    }
}

/// This is a datalink link type.
///
/// As an example, `Linktype(1)` is ethernet. A full list of linktypes is available
/// [here](http://www.tcpdump.org/linktypes.html). The const bellow are not exhaustive.
/// ```rust
/// use pcap::Linktype;
///
/// let lt = Linktype(1);
/// assert_eq!(Linktype::ETHERNET, lt);
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Linktype(pub i32);

impl Linktype {
    /// Gets the name of the link type, such as EN10MB
    pub fn get_name(&self) -> Result<String, Error> {
        unsafe { cstr_to_string(raw::pcap_datalink_val_to_name(self.0)) }?.ok_or(InvalidLinktype)
    }

    /// Gets the description of a link type.
    pub fn get_description(&self) -> Result<String, Error> {
        unsafe { cstr_to_string(raw::pcap_datalink_val_to_description(self.0)) }?
            .ok_or(InvalidLinktype)
    }

    /// Gets the linktype from a name string
    pub fn from_name(name: &str) -> Result<Linktype, Error> {
        let name = CString::new(name)?;
        let val = unsafe { raw::pcap_datalink_name_to_val(name.as_ptr()) };
        if val == -1 {
            return Err(InvalidLinktype);
        }

        Ok(Linktype(val))
    }

    pub const NULL: Self = Self(0);
    pub const ETHERNET: Self = Self(1);
    pub const AX25: Self = Self(3);
    pub const IEEE802_5: Self = Self(6);
    pub const ARCNET_BSD: Self = Self(7);
    pub const SLIP: Self = Self(8);
    pub const PPP: Self = Self(9);
    pub const FDDI: Self = Self(10);
    pub const PPP_HDLC: Self = Self(50);
    pub const PPP_ETHER: Self = Self(51);
    pub const ATM_RFC1483: Self = Self(100);
    pub const RAW: Self = Self(101);
    pub const C_HDLC: Self = Self(104);
    pub const IEEE802_11: Self = Self(105);
    pub const FRELAY: Self = Self(107);
    pub const LOOP: Self = Self(108);
    pub const LINUX_SLL: Self = Self(113);
    pub const LTALK: Self = Self(114);
    pub const PFLOG: Self = Self(117);
    pub const IEEE802_11_PRISM: Self = Self(119);
    pub const IP_OVER_FC: Self = Self(122);
    pub const SUNATM: Self = Self(123);
    pub const IEEE802_11_RADIOTAP: Self = Self(127);
    pub const ARCNET_LINUX: Self = Self(129);
    pub const APPLE_IP_OVER_IEEE1394: Self = Self(138);
    pub const MTP2_WITH_PHDR: Self = Self(139);
    pub const MTP2: Self = Self(140);
    pub const MTP3: Self = Self(141);
    pub const SCCP: Self = Self(142);
    pub const DOCSIS: Self = Self(143);
    pub const LINUX_IRDA: Self = Self(144);
    pub const USER0: Self = Self(147);
    pub const USER1: Self = Self(148);
    pub const USER2: Self = Self(149);
    pub const USER3: Self = Self(150);
    pub const USER4: Self = Self(151);
    pub const USER5: Self = Self(152);
    pub const USER6: Self = Self(153);
    pub const USER7: Self = Self(154);
    pub const USER8: Self = Self(155);
    pub const USER9: Self = Self(156);
    pub const USER10: Self = Self(157);
    pub const USER11: Self = Self(158);
    pub const USER12: Self = Self(159);
    pub const USER13: Self = Self(160);
    pub const USER14: Self = Self(161);
    pub const USER15: Self = Self(162);
    pub const IEEE802_11_AVS: Self = Self(163);
    pub const BACNET_MS_TP: Self = Self(165);
    pub const PPP_PPPD: Self = Self(166);
    pub const GPRS_LLC: Self = Self(169);
    pub const GPF_T: Self = Self(170);
    pub const GPF_F: Self = Self(171);
    pub const LINUX_LAPD: Self = Self(177);
    pub const MFR: Self = Self(182);
    pub const BLUETOOTH_HCI_H4: Self = Self(187);
    pub const USB_LINUX: Self = Self(189);
    pub const PPI: Self = Self(192);
    pub const IEEE802_15_4_WITHFCS: Self = Self(195);
    pub const SITA: Self = Self(196);
    pub const ERF: Self = Self(197);
    pub const BLUETOOTH_HCI_H4_WITH_PHDR: Self = Self(201);
    pub const AX25_KISS: Self = Self(202);
    pub const LAPD: Self = Self(203);
    pub const PPP_WITH_DIR: Self = Self(204);
    pub const C_HDLC_WITH_DIR: Self = Self(205);
    pub const FRELAY_WITH_DIR: Self = Self(206);
    pub const LAPB_WITH_DIR: Self = Self(207);
    pub const IPMB_LINUX: Self = Self(209);
    pub const IEEE802_15_4_NONASK_PHY: Self = Self(215);
    pub const USB_LINUX_MMAPPED: Self = Self(220);
    pub const FC_2: Self = Self(224);
    pub const FC_2_WITH_FRAME_DELIMS: Self = Self(225);
    pub const IPNET: Self = Self(226);
    pub const CAN_SOCKETCAN: Self = Self(227);
    pub const IPV4: Self = Self(228);
    pub const IPV6: Self = Self(229);
    pub const IEEE802_15_4_NOFCS: Self = Self(230);
    pub const DBUS: Self = Self(231);
    pub const DVB_CI: Self = Self(235);
    pub const MUX27010: Self = Self(236);
    pub const STANAG_5066_D_PDU: Self = Self(237);
    pub const NFLOG: Self = Self(239);
    pub const NETANALYZER: Self = Self(240);
    pub const NETANALYZER_TRANSPARENT: Self = Self(241);
    pub const IPOIB: Self = Self(242);
    pub const MPEG_2_TS: Self = Self(243);
    pub const NG40: Self = Self(244);
    pub const NFC_LLCP: Self = Self(245);
    pub const INFINIBAND: Self = Self(247);
    pub const SCTP: Self = Self(248);
    pub const USBPCAP: Self = Self(249);
    pub const RTAC_SERIAL: Self = Self(250);
    pub const BLUETOOTH_LE_LL: Self = Self(251);
    pub const NETLINK: Self = Self(253);
    pub const BLUETOOTH_LINUX_MONITOR: Self = Self(254);
    pub const BLUETOOTH_BREDR_BB: Self = Self(255);
    pub const BLUETOOTH_LE_LL_WITH_PHDR: Self = Self(256);
    pub const PROFIBUS_DL: Self = Self(257);
    pub const PKTAP: Self = Self(258);
    pub const EPON: Self = Self(259);
    pub const IPMI_HPM_2: Self = Self(260);
    pub const ZWAVE_R1_R2: Self = Self(261);
    pub const ZWAVE_R3: Self = Self(262);
    pub const WATTSTOPPER_DLM: Self = Self(263);
    pub const ISO_14443: Self = Self(264);
    pub const RDS: Self = Self(265);
    pub const USB_DARWIN: Self = Self(266);
    pub const SDLC: Self = Self(268);
    pub const LORATAP: Self = Self(270);
    pub const VSOCK: Self = Self(271);
    pub const NORDIC_BLE: Self = Self(272);
    pub const DOCSIS31_XRA31: Self = Self(273);
    pub const ETHERNET_MPACKET: Self = Self(274);
    pub const DISPLAYPORT_AUX: Self = Self(275);
    pub const LINUX_SLL2: Self = Self(276);
    pub const OPENVIZSLA: Self = Self(278);
    pub const EBHSCR: Self = Self(279);
    pub const VPP_DISPATCH: Self = Self(280);
    pub const DSA_TAG_BRCM: Self = Self(281);
    pub const DSA_TAG_BRCM_PREPEND: Self = Self(282);
    pub const IEEE802_15_4_TAP: Self = Self(283);
    pub const DSA_TAG_DSA: Self = Self(284);
    pub const DSA_TAG_EDSA: Self = Self(285);
    pub const ELEE: Self = Self(286);
    pub const Z_WAVE_SERIAL: Self = Self(287);
    pub const USB_2_0: Self = Self(288);
    pub const ATSC_ALP: Self = Self(289);
}

/// Represents a packet returned from pcap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet<'a> {
    /// The packet header provided by pcap, including the timeval, captured length, and packet
    /// length
    pub header: &'a PacketHeader,
    /// The captured packet data
    pub data: &'a [u8],
}

impl<'a> Packet<'a> {
    #[doc(hidden)]
    pub fn new(header: &'a PacketHeader, data: &'a [u8]) -> Packet<'a> {
        Packet { header, data }
    }
}

impl<'b> Deref for Packet<'b> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.data
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
/// Represents a packet header provided by pcap, including the timeval, caplen and len.
pub struct PacketHeader {
    /// The time when the packet was captured
    pub ts: libc::timeval,
    /// The number of bytes of the packet that are available from the capture
    pub caplen: u32,
    /// The length of the packet, in bytes (which might be more than the number of bytes available
    /// from the capture, if the length of the packet is larger than the maximum number of bytes to
    /// capture)
    pub len: u32,
}

impl fmt::Debug for PacketHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "PacketHeader {{ ts: {}.{:06}, caplen: {}, len: {} }}",
            self.ts.tv_sec, self.ts.tv_usec, self.caplen, self.len
        )
    }
}

impl PartialEq for PacketHeader {
    fn eq(&self, rhs: &PacketHeader) -> bool {
        self.ts.tv_sec == rhs.ts.tv_sec
            && self.ts.tv_usec == rhs.ts.tv_usec
            && self.caplen == rhs.caplen
            && self.len == rhs.len
    }
}

impl Eq for PacketHeader {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Packet statistics for a capture
pub struct Stat {
    /// Number of packets received
    pub received: u32,
    /// Number of packets dropped because there was no room in the operating system's buffer when
    /// they arrived, because packets weren't being read fast enough
    pub dropped: u32,
    /// Number of packets dropped by the network interface or its driver
    pub if_dropped: u32,
}

impl Stat {
    fn new(received: u32, dropped: u32, if_dropped: u32) -> Stat {
        Stat {
            received,
            dropped,
            if_dropped,
        }
    }
}

#[repr(u32)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
/// Timestamp resolution types
///
/// Not all systems and interfaces will necessarily support all of these resolutions when doing
/// live captures; all of them can be requested when reading a safefile.
pub enum Precision {
    /// Use timestamps with microsecond precision. This is the default.
    Micro = 0,
    /// Use timestamps with nanosecond precision.
    Nano = 1,
}

/// Phantom type representing an inactive capture handle.
pub enum Inactive {}

/// Phantom type representing an active capture handle.
pub enum Active {}

/// Phantom type representing an offline capture handle, from a pcap dump file.
/// Implements `Activated` because it behaves nearly the same as a live handle.
pub enum Offline {}

/// Phantom type representing a dead capture handle.  This can be use to create
/// new save files that are not generated from an active capture.
/// Implements `Activated` because it behaves nearly the same as a live handle.
pub enum Dead {}

/// `Capture`s can be in different states at different times, and in these states they
/// may or may not have particular capabilities. This trait is implemented by phantom
/// types which allows us to punt these invariants to the type system to avoid runtime
/// errors.
pub unsafe trait Activated: State {}

unsafe impl Activated for Active {}

unsafe impl Activated for Offline {}

unsafe impl Activated for Dead {}

/// `Capture`s can be in different states at different times, and in these states they
/// may or may not have particular capabilities. This trait is implemented by phantom
/// types which allows us to punt these invariants to the type system to avoid runtime
/// errors.
pub unsafe trait State {}

unsafe impl State for Inactive {}

unsafe impl State for Active {}

unsafe impl State for Offline {}

unsafe impl State for Dead {}

/// This is a pcap capture handle which is an abstraction over the `pcap_t` provided by pcap.
/// There are many ways to instantiate and interact with a pcap handle, so phantom types are
/// used to express these behaviors.
///
/// **`Capture<Inactive>`** is created via `Capture::from_device()`. This handle is inactive,
/// so you cannot (yet) obtain packets from it. However, you can configure things like the
/// buffer size, snaplen, timeout, and promiscuity before you activate it.
///
/// **`Capture<Active>`** is created by calling `.open()` on a `Capture<Inactive>`. This
/// activates the capture handle, allowing you to get packets with `.next()` or apply filters
/// with `.filter()`.
///
/// **`Capture<Offline>`** is created via `Capture::from_file()`. This allows you to read a
/// pcap format dump file as if you were opening an interface -- very useful for testing or
/// analysis.
///
/// **`Capture<Dead>`** is created via `Capture::dead()`. This allows you to create a pcap
/// format dump file without needing an active capture.
///
/// # Example:
///
/// ```ignore
/// let cap = Capture::from_device(Device::lookup().unwrap()) // open the "default" interface
///               .unwrap() // assume the device exists and we are authorized to open it
///               .open() // activate the handle
///               .unwrap(); // assume activation worked
///
/// while let Ok(packet) = cap.next() {
///     println!("received packet! {:?}", packet);
/// }
/// ```
pub struct Capture<T: State + ?Sized> {
    nonblock: bool,
    handle: Unique<raw::pcap_t>,
    _marker: PhantomData<T>,
}

impl<T: State + ?Sized> Capture<T> {
    unsafe fn from_handle(handle: *mut raw::pcap_t) -> Capture<T> {
        Capture {
            nonblock: false,
            handle: Unique::new(handle),
            _marker: PhantomData,
        }
    }

    fn new_raw<F>(path: Option<&str>, func: F) -> Result<Capture<T>, Error>
    where
        F: FnOnce(*const libc::c_char, *mut libc::c_char) -> *mut raw::pcap_t,
    {
        with_errbuf(|err| {
            let handle = match path {
                None => func(ptr::null(), err),
                Some(path) => {
                    let path = CString::new(path)?;
                    func(path.as_ptr(), err)
                }
            };
            unsafe { handle.as_mut() }
                .map(|h| unsafe { Capture::from_handle(h) })
                .ok_or_else(|| unsafe { Error::new(err) })
        })
    }

    /// Set the minumum amount of data received by the kernel in a single call.
    ///
    /// Note that this value is set to 0 when the capture is set to immediate mode. You should not
    /// call `min_to_copy` on captures in immediate mode if you want them to stay in immediate mode.
    #[cfg(windows)]
    pub fn min_to_copy(self, to: i32) -> Capture<T> {
        unsafe {
            raw::pcap_setmintocopy(*self.handle, to as _);
        }
        self
    }

    #[inline]
    fn check_err(&self, success: bool) -> Result<(), Error> {
        if success {
            Ok(())
        } else {
            Err(unsafe { Error::new(raw::pcap_geterr(*self.handle)) })
        }
    }
}

impl Capture<Offline> {
    /// Opens an offline capture handle from a pcap dump file, given a path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Capture<Offline>, Error> {
        Capture::new_raw(path.as_ref().to_str(), |path, err| unsafe {
            raw::pcap_open_offline(path, err)
        })
    }

    /// Opens an offline capture handle from a pcap dump file, given a path.
    /// Takes an additional precision argument specifying the time stamp precision desired.
    #[cfg(libpcap_1_5_0)]
    pub fn from_file_with_precision<P: AsRef<Path>>(
        path: P,
        precision: Precision,
    ) -> Result<Capture<Offline>, Error> {
        Capture::new_raw(path.as_ref().to_str(), |path, err| unsafe {
            raw::pcap_open_offline_with_tstamp_precision(path, precision as _, err)
        })
    }

    /// Opens an offline capture handle from a pcap dump file, given a file descriptor.
    ///
    /// # Safety
    ///
    /// Unsafe, because the returned Capture assumes it is the sole owner of the file descriptor.
    #[cfg(not(windows))]
    pub unsafe fn from_raw_fd(fd: RawFd) -> Result<Capture<Offline>, Error> {
        open_raw_fd(fd, b'r')
            .and_then(|file| Capture::new_raw(None, |_, err| raw::pcap_fopen_offline(file, err)))
    }

    /// Opens an offline capture handle from a pcap dump file, given a file descriptor. Takes an
    /// additional precision argument specifying the time stamp precision desired.
    ///
    /// # Safety
    ///
    /// Unsafe, because the returned Capture assumes it is the sole owner of the file descriptor.
    #[cfg(all(not(windows), libpcap_1_5_0))]
    pub unsafe fn from_raw_fd_with_precision(
        fd: RawFd,
        precision: Precision,
    ) -> Result<Capture<Offline>, Error> {
        open_raw_fd(fd, b'r').and_then(|file| {
            Capture::new_raw(None, |_, err| {
                raw::pcap_fopen_offline_with_tstamp_precision(file, precision as _, err)
            })
        })
    }
}

#[repr(i32)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
/// Timestamp types
///
/// Not all systems and interfaces will necessarily support all of these.
///
/// Note that time stamps synchronized with the system clock can go backwards, as the system clock
/// can go backwards.  If a clock is not in sync with the system clock, that could be because the
/// system clock isn't keeping accurate time, because the other clock isn't keeping accurate time,
/// or both.
///
/// Note that host-provided time stamps generally correspond to the time when the time-stamping
/// code sees the packet; this could be some unknown amount of time after the first or last bit of
/// the packet is received by the network adapter, due to batching of interrupts for packet
/// arrival, queueing delays, etc..
pub enum TimestampType {
    /// Timestamps are provided by the host machine, rather than by the capture device.
    ///
    /// The characteristics of the timestamp are unknown.
    Host = 0,
    /// A timestamp provided by the host machine that is low precision but relatively cheap to
    /// fetch.
    ///
    /// This is normally done using the system clock, so it's normally synchornized with times
    /// you'd fetch from system calls.
    HostLowPrec = 1,
    /// A timestamp provided by the host machine that is high precision. It might be more expensive
    /// to fetch.
    ///
    /// The timestamp might or might not be synchronized with the system clock, and might have
    /// problems with time stamps for packets received on different CPUs, depending on the
    /// platform.
    HostHighPrec = 2,
    /// The timestamp is a high-precision time stamp supplied by the capture device.
    ///
    /// The timestamp is synchronized with the system clock.
    Adapter = 3,
    /// The timestamp is a high-precision time stamp supplied by the capture device.
    ///
    /// The timestamp is not synchronized with the system clock.
    AdapterUnsynced = 4,
}

#[deprecated(note = "Renamed to TimestampType")]
/// An old name for `TimestampType`, kept around for backward-compatibility.
pub type TstampType = TimestampType;

#[repr(u32)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
/// The direction of packets to be captured. Use with `Capture::direction`.
pub enum Direction {
    /// Capture packets received by or sent by the device. This is the default.
    InOut = raw::PCAP_D_INOUT,
    /// Only capture packets received by the device.
    In = raw::PCAP_D_IN,
    /// Only capture packets sent by the device.
    Out = raw::PCAP_D_OUT,
}

impl Capture<Inactive> {
    /// Opens a capture handle for a device. You can pass a `Device` or an `&str` device
    /// name here. The handle is inactive, but can be activated via `.open()`.
    ///
    /// # Example
    /// ```
    /// use pcap::*;
    ///
    /// // Usage 1: Capture from a single owned device
    /// let dev: Device = pcap::Device::lookup().unwrap();
    /// let cap1 = Capture::from_device(dev);
    ///
    /// // Usage 2: Capture from an element of device list.
    /// let list: Vec<Device> = pcap::Device::list().unwrap();
    /// let cap2 = Capture::from_device(list[0].clone());
    ///
    /// // Usage 3: Capture from `&str` device name
    /// let cap3 = Capture::from_device("eth0");
    /// ```
    pub fn from_device<D: Into<Device>>(device: D) -> Result<Capture<Inactive>, Error> {
        let device: Device = device.into();
        Capture::new_raw(Some(&device.name), |name, err| unsafe {
            raw::pcap_create(name, err)
        })
    }

    /// Activates an inactive capture created from `Capture::from_device()` or returns
    /// an error.
    pub fn open(self) -> Result<Capture<Active>, Error> {
        unsafe {
            self.check_err(raw::pcap_activate(*self.handle) == 0)?;
            Ok(mem::transmute(self))
        }
    }

    /// Set the read timeout for the Capture. By default, this is 0, so it will block
    /// indefinitely.
    pub fn timeout(self, ms: i32) -> Capture<Inactive> {
        unsafe { raw::pcap_set_timeout(*self.handle, ms) };
        self
    }

    /// Set the time stamp type to be used by a capture device.
    #[cfg(libpcap_1_2_1)]
    pub fn tstamp_type(self, tstamp_type: TimestampType) -> Capture<Inactive> {
        unsafe { raw::pcap_set_tstamp_type(*self.handle, tstamp_type as _) };
        self
    }

    /// Set promiscuous mode on or off. By default, this is off.
    pub fn promisc(self, to: bool) -> Capture<Inactive> {
        unsafe { raw::pcap_set_promisc(*self.handle, to as _) };
        self
    }

    /// Set immediate mode on or off. By default, this is off.
    ///
    /// Note that in WinPcap immediate mode is set by passing a 0 argument to `min_to_copy`.
    /// Immediate mode will be unset if `min_to_copy` is later called with a non-zero argument.
    /// Immediate mode is unset by resetting `min_to_copy` to the WinPcap default possibly changing
    /// a previously set value. When using `min_to_copy`, it is best to avoid `immediate_mode`.
    #[cfg(any(libpcap_1_5_0, windows))]
    pub fn immediate_mode(self, to: bool) -> Capture<Inactive> {
        // Prior to 1.5.0 when `pcap_set_immediate_mode` was introduced, the necessary steps to set
        // immediate mode were more complicated, depended on the OS, and in some configurations had
        // to be set on an active capture. See
        // https://www.tcpdump.org/manpages/pcap_set_immediate_mode.3pcap.html. Since we do not
        // expect pre-1.5.0 version on unix systems in the wild, we simply ignore those cases.
        #[cfg(libpcap_1_5_0)]
        unsafe {
            raw::pcap_set_immediate_mode(*self.handle, to as _)
        };

        // In WinPcap we use `pcap_setmintocopy` as it does not have `pcap_set_immediate_mode`.
        #[cfg(all(windows, not(libpcap_1_5_0)))]
        unsafe {
            raw::pcap_setmintocopy(
                *self.handle,
                if to {
                    0
                } else {
                    raw::WINPCAP_MINTOCOPY_DEFAULT
                },
            )
        };

        self
    }

    /// Set rfmon mode on or off. The default is maintained by pcap.
    #[cfg(not(windows))]
    pub fn rfmon(self, to: bool) -> Capture<Inactive> {
        unsafe { raw::pcap_set_rfmon(*self.handle, to as _) };
        self
    }

    /// Set the buffer size for incoming packet data.
    ///
    /// The default is 1000000. This should always be larger than the snaplen.
    pub fn buffer_size(self, to: i32) -> Capture<Inactive> {
        unsafe { raw::pcap_set_buffer_size(*self.handle, to) };
        self
    }

    /// Set the time stamp precision returned in captures.
    #[cfg(libpcap_1_5_0)]
    pub fn precision(self, precision: Precision) -> Capture<Inactive> {
        unsafe { raw::pcap_set_tstamp_precision(*self.handle, precision as _) };
        self
    }

    /// Set the snaplen size (the maximum length of a packet captured into the buffer).
    /// Useful if you only want certain headers, but not the entire packet.
    ///
    /// The default is 65535.
    pub fn snaplen(self, to: i32) -> Capture<Inactive> {
        unsafe { raw::pcap_set_snaplen(*self.handle, to) };
        self
    }
}

///# Activated captures include `Capture<Active>` and `Capture<Offline>`.
impl<T: Activated + ?Sized> Capture<T> {
    /// List the datalink types that this captured device supports.
    pub fn list_datalinks(&self) -> Result<Vec<Linktype>, Error> {
        unsafe {
            let mut links: *mut i32 = ptr::null_mut();
            let num = raw::pcap_list_datalinks(*self.handle, &mut links);
            let mut vec = vec![];
            if num > 0 {
                vec.extend(
                    slice::from_raw_parts(links, num as _)
                        .iter()
                        .cloned()
                        .map(Linktype),
                )
            }
            raw::pcap_free_datalinks(links);
            self.check_err(num > 0).and(Ok(vec))
        }
    }

    /// Set the datalink type for the current capture handle.
    pub fn set_datalink(&mut self, linktype: Linktype) -> Result<(), Error> {
        self.check_err(unsafe { raw::pcap_set_datalink(*self.handle, linktype.0) == 0 })
    }

    /// Get the current datalink type for this capture handle.
    pub fn get_datalink(&self) -> Linktype {
        unsafe { Linktype(raw::pcap_datalink(*self.handle)) }
    }

    /// Create a `Savefile` context for recording captured packets using this `Capture`'s
    /// configurations.
    pub fn savefile<P: AsRef<Path>>(&self, path: P) -> Result<Savefile, Error> {
        let name = CString::new(path.as_ref().to_str().unwrap())?;
        let handle = unsafe { raw::pcap_dump_open(*self.handle, name.as_ptr()) };
        self.check_err(!handle.is_null())
            .map(|_| unsafe { Savefile::from_handle(handle) })
    }

    /// Create a `Savefile` context for recording captured packets using this `Capture`'s
    /// configurations. The output is written to a raw file descriptor which is opened in `"w"`
    /// mode.
    ///
    /// # Safety
    ///
    /// Unsafe, because the returned Savefile assumes it is the sole owner of the file descriptor.
    #[cfg(not(windows))]
    pub unsafe fn savefile_raw_fd(&self, fd: RawFd) -> Result<Savefile, Error> {
        open_raw_fd(fd, b'w').and_then(|file| {
            let handle = raw::pcap_dump_fopen(*self.handle, file);
            self.check_err(!handle.is_null())
                .map(|_| Savefile::from_handle(handle))
        })
    }

    /// Reopen a `Savefile` context for recording captured packets using this `Capture`'s
    /// configurations. This is similar to `savefile()` but does not create the file if it
    /// does  not exist and, if it does already exist, and is a pcap file with the same
    /// byte order as the host opening the file, and has the same time stamp precision,
    /// link-layer header type,  and  snapshot length as p, it will write new packets
    /// at the end of the file.
    #[cfg(libpcap_1_7_2)]
    pub fn savefile_append<P: AsRef<Path>>(&self, path: P) -> Result<Savefile, Error> {
        let name = CString::new(path.as_ref().to_str().unwrap())?;
        let handle = unsafe { raw::pcap_dump_open_append(*self.handle, name.as_ptr()) };
        self.check_err(!handle.is_null())
            .map(|_| unsafe { Savefile::from_handle(handle) })
    }

    /// Set the direction of the capture
    pub fn direction(&self, direction: Direction) -> Result<(), Error> {
        self.check_err(unsafe { raw::pcap_setdirection(*self.handle, direction as u32 as _) == 0 })
    }

    /// Blocks until a packet is returned from the capture handle or an error occurs.
    ///
    /// pcap captures packets and places them into a buffer which this function reads
    /// from. This buffer has a finite length, so if the buffer fills completely new
    /// packets will be discarded temporarily. This means that in realtime situations,
    /// you probably want to minimize the time between calls of this next() method.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Result<Packet, Error> {
        unsafe {
            let mut header: *mut raw::pcap_pkthdr = ptr::null_mut();
            let mut packet: *const libc::c_uchar = ptr::null();
            let retcode = raw::pcap_next_ex(*self.handle, &mut header, &mut packet);
            self.check_err(retcode != -1)?; // -1 => an error occured while reading the packet
            match retcode {
                i if i >= 1 => {
                    // packet was read without issue
                    Ok(Packet::new(
                        &*(&*header as *const raw::pcap_pkthdr as *const PacketHeader),
                        slice::from_raw_parts(packet, (*header).caplen as _),
                    ))
                }
                0 => {
                    // packets are being read from a live capture and the
                    // timeout expired
                    Err(TimeoutExpired)
                }
                -2 => {
                    // packets are being read from a "savefile" and there are no
                    // more packets to read
                    Err(NoMorePackets)
                }
                _ => {
                    // libpcap only defines codes >=1, 0, -1, and -2
                    unreachable!()
                }
            }
        }
    }

    #[cfg(feature = "capture-stream")]
    fn next_noblock<'a>(
        &'a mut self,
        cx: &mut core::task::Context,
        fd: &mut tokio::io::unix::AsyncFd<stream::SelectableFd>,
    ) -> Result<Packet<'a>, Error> {
        let ready = fd.poll_read_ready(cx);
        if ready.is_pending() {
            Err(IoError(io::ErrorKind::WouldBlock))
        } else {
            match self.next() {
                Ok(p) => Ok(p),
                Err(TimeoutExpired) => {
                    // Per https://docs.rs/tokio/1.12.0/tokio/io/unix/struct.AsyncFd.html
                    // ... it is critical to ensure that this ready flag
                    // is cleared when (and only when) the file descriptor
                    // ceases to be ready.
                    //
                    if let Ready(Ok(mut guard)) = ready {
                        guard.clear_ready();
                        #[allow(unused_must_use)]
                        {
                            fd.poll_read_ready(cx);
                        }
                    }

                    Err(IoError(io::ErrorKind::WouldBlock))
                }
                Err(e) => Err(e),
            }
        }
    }

    #[cfg(feature = "capture-stream")]
    pub fn stream<C: stream::PacketCodec>(
        self,
        codec: C,
    ) -> Result<stream::PacketStream<T, C>, Error> {
        if !self.nonblock {
            return Err(NonNonBlock);
        }
        unsafe {
            let fd = raw::pcap_get_selectable_fd(*self.handle);
            stream::PacketStream::new(self, fd, codec)
        }
    }

    /// Adds a filter to the capture using the given BPF program string. Internally
    /// this is compiled using `pcap_compile()`.
    ///
    /// See http://biot.com/capstats/bpf.html for more information about this syntax.
    pub fn filter(&mut self, program: &str, optimize: bool) -> Result<(), Error> {
        let program = CString::new(program)?;
        unsafe {
            let mut bpf_program: raw::bpf_program = mem::zeroed();
            let ret = raw::pcap_compile(
                *self.handle,
                &mut bpf_program,
                program.as_ptr(),
                optimize as libc::c_int,
                0,
            );
            self.check_err(ret != -1)?;
            let ret = raw::pcap_setfilter(*self.handle, &mut bpf_program);
            raw::pcap_freecode(&mut bpf_program);
            self.check_err(ret != -1)
        }
    }

    /// Get capture statistics about this capture. The values represent packet statistics from the
    /// start of the run to the time of the call.
    ///
    /// See https://www.tcpdump.org/manpages/pcap_stats.3pcap.html for per-platform caveats about
    /// how packet statistics are calculated.
    pub fn stats(&mut self) -> Result<Stat, Error> {
        unsafe {
            let mut stats: raw::pcap_stat = mem::zeroed();
            self.check_err(raw::pcap_stats(*self.handle, &mut stats) != -1)
                .map(|_| Stat::new(stats.ps_recv, stats.ps_drop, stats.ps_ifdrop))
        }
    }
}

impl Capture<Active> {
    /// Sends a packet over this capture handle's interface.
    pub fn sendpacket<B: Borrow<[u8]>>(&mut self, buf: B) -> Result<(), Error> {
        let buf = buf.borrow();
        self.check_err(unsafe {
            raw::pcap_sendpacket(*self.handle, buf.as_ptr() as _, buf.len() as _) == 0
        })
    }

    /// Set the capture to be non-blocking. When this is set, next() may return an error indicating
    /// that there is no packet available to be read.
    pub fn setnonblock(mut self) -> Result<Capture<Active>, Error> {
        with_errbuf(|err| unsafe {
            if raw::pcap_setnonblock(*self.handle, 1, err) != 0 {
                return Err(Error::new(err));
            }
            self.nonblock = true;
            Ok(self)
        })
    }
}

impl Capture<Dead> {
    /// Creates a "fake" capture handle for the given link type.
    pub fn dead(linktype: Linktype) -> Result<Capture<Dead>, Error> {
        unsafe { raw::pcap_open_dead(linktype.0, 65535).as_mut() }
            .map(|h| unsafe { Capture::from_handle(h) })
            .ok_or(InsufficientMemory)
    }

    /// Compiles the string into a filter program using `pcap_compile`.
    pub fn compile(&self, program: &str, optimize: bool) -> Result<BpfProgram, Error> {
        let program = CString::new(program).unwrap();

        unsafe {
            let mut bpf_program: raw::bpf_program = mem::zeroed();
            if -1
                == raw::pcap_compile(
                    *self.handle,
                    &mut bpf_program,
                    program.as_ptr(),
                    optimize as libc::c_int,
                    0,
                )
            {
                return Err(Error::new(raw::pcap_geterr(*self.handle)));
            }
            Ok(BpfProgram(bpf_program))
        }
    }
}

#[cfg(not(windows))]
impl AsRawFd for Capture<Active> {
    fn as_raw_fd(&self) -> RawFd {
        unsafe {
            let fd = raw::pcap_fileno(*self.handle);

            match fd {
                -1 => {
                    panic!("Unable to get file descriptor for live capture");
                }
                fd => fd,
            }
        }
    }
}

impl<T: State + ?Sized> Drop for Capture<T> {
    fn drop(&mut self) {
        unsafe { raw::pcap_close(*self.handle) }
    }
}

impl<T: Activated> From<Capture<T>> for Capture<dyn Activated> {
    fn from(cap: Capture<T>) -> Capture<dyn Activated> {
        unsafe { mem::transmute(cap) }
    }
}

/// Abstraction for writing pcap savefiles, which can be read afterwards via `Capture::from_file()`.
pub struct Savefile {
    handle: Unique<raw::pcap_dumper_t>,
}

impl Savefile {
    /// Write a packet to a capture file
    pub fn write(&mut self, packet: &Packet) {
        unsafe {
            raw::pcap_dump(
                *self.handle as _,
                &*(packet.header as *const PacketHeader as *const raw::pcap_pkthdr),
                packet.data.as_ptr(),
            );
        }
    }

    /// Flushes all the packets that haven't been written to the savefile
    pub fn flush(&mut self) -> Result<(), Error> {
        if unsafe { raw::pcap_dump_flush(*self.handle as _) } != 0 {
            return Err(Error::ErrnoError(errno::errno()));
        }

        Ok(())
    }
}

impl Savefile {
    unsafe fn from_handle(handle: *mut raw::pcap_dumper_t) -> Savefile {
        Savefile {
            handle: Unique::new(handle),
        }
    }
}

impl Drop for Savefile {
    fn drop(&mut self) {
        unsafe { raw::pcap_dump_close(*self.handle) }
    }
}

#[cfg(not(windows))]
/// Open a raw file descriptor.
///
/// # Safety
///
/// Unsafe, because the returned FILE assumes it is the sole owner of the file descriptor.
pub unsafe fn open_raw_fd(fd: RawFd, mode: u8) -> Result<*mut libc::FILE, Error> {
    let mode = vec![mode, 0];
    libc::fdopen(fd, mode.as_ptr() as _)
        .as_mut()
        .map(|f| f as _)
        .ok_or(InvalidRawFd)
}

#[inline]
unsafe fn cstr_to_string(ptr: *const libc::c_char) -> Result<Option<String>, Error> {
    let string = if ptr.is_null() {
        None
    } else {
        Some(CStr::from_ptr(ptr as _).to_str()?.to_owned())
    };
    Ok(string)
}

#[cfg(target_os = "windows")]
#[allow(clippy::unnecessary_wraps)]
#[inline]
unsafe fn wstr_to_string(ptr: *const libc::c_char) -> Result<Option<String>, Error> {
    let string = if ptr.is_null() {
        None
    } else {
        Some(WideCString::from_ptr_str(ptr as _).to_string().unwrap())
    };
    Ok(string)
}

#[inline]
fn with_errbuf<T, F>(func: F) -> Result<T, Error>
where
    F: FnOnce(*mut libc::c_char) -> Result<T, Error>,
{
    let mut errbuf = [0i8; 256];
    func(errbuf.as_mut_ptr() as _)
}

#[test]
fn test_struct_size() {
    use std::mem::size_of;
    assert_eq!(size_of::<PacketHeader>(), size_of::<raw::pcap_pkthdr>());
}

pub struct BpfInstruction(raw::bpf_insn);
pub struct BpfProgram(raw::bpf_program);

impl BpfProgram {
    /// checks whether a filter matches a packet
    pub fn filter(&self, buf: &[u8]) -> bool {
        let header: raw::pcap_pkthdr = raw::pcap_pkthdr {
            ts: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            caplen: buf.len() as u32,
            len: buf.len() as u32,
        };
        unsafe { raw::pcap_offline_filter(&self.0, &header, buf.as_ptr()) > 0 }
    }

    pub fn get_instructions(&self) -> &[BpfInstruction] {
        unsafe {
            slice::from_raw_parts(
                self.0.bf_insns as *const BpfInstruction,
                self.0.bf_len as usize,
            )
        }
    }
}

impl Clone for BpfProgram {
    // make a deep copy of the underlying program
    fn clone(&self) -> Self {
        let len = self.0.bf_len as usize;
        let size = len * mem::size_of::<raw::bpf_insn>();
        let storage = unsafe {
            let storage = libc::malloc(size) as *mut raw::bpf_insn;
            ptr::copy_nonoverlapping(self.0.bf_insns, storage, len);
            storage
        };
        BpfProgram(raw::bpf_program {
            bf_len: self.0.bf_len,
            bf_insns: storage,
        })
    }
}

impl Drop for BpfProgram {
    fn drop(&mut self) {
        unsafe { raw::pcap_freecode(&mut self.0) }
    }
}

impl fmt::Display for BpfInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.0.code, self.0.jt, self.0.jf, self.0.k
        )
    }
}

unsafe impl Send for BpfProgram {}
