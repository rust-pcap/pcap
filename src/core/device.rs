use std::{convert::TryFrom, net::IpAddr, ptr};

use bitflags::bitflags;

#[cfg(target_os = "windows")]
use windows_sys::Win32::Networking::WinSock::{SOCKADDR_IN, SOCKADDR_IN6};

use crate::{
    core::capture::{Active, Capture},
    raw, Error,
};

bitflags! {
    /// Network device flags.
    pub struct IfFlags: u32 {
        /// Set if the device is a loopback interface
        const LOOPBACK = raw::PCAP_IF_LOOPBACK;
        /// Set if the device is up
        const UP = raw::PCAP_IF_UP;
        /// Set if the device is running
        const RUNNING = raw::PCAP_IF_RUNNING;
        /// Set if the device is a wireless interface; this includes IrDA as well as radio-based
        /// networks such as IEEE 802.15.4 and IEEE 802.11, so it doesn't just mean Wi-Fi
        const WIRELESS = raw::PCAP_IF_WIRELESS;
    }
}

impl From<u32> for IfFlags {
    fn from(flags: u32) -> Self {
        IfFlags::from_bits_truncate(flags)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Indication of whether the adapter is connected or not; for wireless interfaces, "connected"
/// means "associated with a network".
pub enum ConnectionStatus {
    /// It's unknown whether the adapter is connected or not
    Unknown,
    /// The adapter is connected
    Connected,
    /// The adapter is disconnected
    Disconnected,
    /// The notion of "connected" and "disconnected" don't apply to this interface; for example, it
    /// doesn't apply to a loopback device
    NotApplicable,
}

impl From<u32> for ConnectionStatus {
    fn from(flags: u32) -> Self {
        match flags & raw::PCAP_IF_CONNECTION_STATUS {
            raw::PCAP_IF_CONNECTION_STATUS_UNKNOWN => ConnectionStatus::Unknown,
            raw::PCAP_IF_CONNECTION_STATUS_CONNECTED => ConnectionStatus::Connected,
            raw::PCAP_IF_CONNECTION_STATUS_DISCONNECTED => ConnectionStatus::Disconnected,
            raw::PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE => ConnectionStatus::NotApplicable,
            // DeviceFlags::CONNECTION_STATUS should be a 2-bit mask which means that the four
            // values should cover all the possibilities.
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DeviceFlags {
    pub if_flags: IfFlags,
    pub connection_status: ConnectionStatus,
}

impl From<u32> for DeviceFlags {
    fn from(flags: u32) -> Self {
        DeviceFlags {
            if_flags: flags.into(),
            connection_status: flags.into(),
        }
    }
}

impl DeviceFlags {
    pub fn empty() -> Self {
        DeviceFlags {
            if_flags: IfFlags::empty(),
            connection_status: ConnectionStatus::Unknown,
        }
    }

    pub fn contains(&self, if_flags: IfFlags) -> bool {
        self.if_flags.contains(if_flags)
    }

    pub fn is_loopback(&self) -> bool {
        self.contains(IfFlags::LOOPBACK)
    }

    pub fn is_up(&self) -> bool {
        self.contains(IfFlags::UP)
    }

    pub fn is_running(&self) -> bool {
        self.contains(IfFlags::RUNNING)
    }

    pub fn is_wireless(&self) -> bool {
        self.contains(IfFlags::WIRELESS)
    }
}

#[derive(Debug, Clone)]
/// A network device name and pcap's description of it.
pub struct Device {
    /// The name of the interface
    pub name: String,
    /// A textual description of the interface, if available
    pub desc: Option<String>,
    /// Addresses associated with this interface
    pub addresses: Vec<Address>,
    /// Interface flags
    pub flags: DeviceFlags,
}

impl Device {
    fn new(
        name: String,
        desc: Option<String>,
        addresses: Vec<Address>,
        flags: DeviceFlags,
    ) -> Device {
        Device {
            name,
            desc,
            addresses,
            flags,
        }
    }

    /// Opens a `Capture<Active>` on this device.
    pub fn open(self) -> Result<Capture<Active>, Error> {
        Capture::from_device(self)?.open()
    }

    /// Returns the default Device suitable for captures according to pcap_findalldevs,
    /// or an error from pcap. Note that there may be no suitable devices.
    pub fn lookup() -> Result<Option<Device>, Error> {
        unsafe {
            Device::with_all_devs(|all_devs| {
                let dev = all_devs;
                Ok(if !dev.is_null() {
                    Some(Device::try_from(&*dev)?)
                } else {
                    None
                })
            })
        }
    }

    /// Returns a vector of `Device`s known by pcap via pcap_findalldevs.
    pub fn list() -> Result<Vec<Device>, Error> {
        unsafe {
            Device::with_all_devs(|all_devs| {
                let mut devices = vec![];
                let mut dev = all_devs;
                while !dev.is_null() {
                    devices.push(Device::try_from(&*dev)?);
                    dev = (*dev).next;
                }
                Ok(devices)
            })
        }
    }

    unsafe fn with_all_devs<T, F>(func: F) -> Result<T, Error>
    where
        F: FnOnce(*mut raw::pcap_if_t) -> Result<T, Error>,
    {
        let all_devs = Error::with_errbuf(|err| {
            let mut all_devs: *mut raw::pcap_if_t = ptr::null_mut();
            if raw::pcap_findalldevs(&mut all_devs, err) != 0 {
                return Err(Error::new(err));
            }
            Ok(all_devs)
        })?;
        let result = func(all_devs);
        raw::pcap_freealldevs(all_devs);
        result
    }
}

impl From<&str> for Device {
    fn from(name: &str) -> Self {
        Device::new(name.into(), None, Vec::new(), DeviceFlags::empty())
    }
}

impl TryFrom<&raw::pcap_if_t> for Device {
    type Error = Error;

    fn try_from(dev: &raw::pcap_if_t) -> Result<Self, Error> {
        Ok(Device::new(
            unsafe { Error::cstr_to_string(dev.name)?.ok_or(Error::InvalidString)? },
            unsafe { Error::cstr_to_string(dev.description)? },
            unsafe { Address::new_vec(dev.addresses) },
            DeviceFlags::from(dev.flags),
        ))
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

        match (*ptr).sa_family as u32 {
            AF_INET => {
                let ptr: *const SOCKADDR_IN = std::mem::transmute(ptr);
                let addr: [u8; 4] = ((*ptr).sin_addr.S_un.S_addr).to_ne_bytes();
                Some(IpAddr::from(addr))
            }
            AF_INET6 => {
                let ptr: *const SOCKADDR_IN6 = std::mem::transmute(ptr);
                let addr = (*ptr).sin6_addr.u.Byte;
                Some(IpAddr::from(addr))
            }

            _ => None,
        }
    }
}
