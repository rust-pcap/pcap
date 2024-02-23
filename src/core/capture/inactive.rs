use std::mem;

use crate::{
    core::{
        capture::{Active, Capture, Inactive, Precision},
        device::Device,
    },
    raw, Error,
};

impl Capture<Inactive> {
    /// Opens a capture handle for a device. You can pass a `Device` or an `&str` device
    /// name here. The handle is inactive, but can be activated via `.open()`.
    ///
    /// # Example
    /// ```
    /// use pcap::*;
    ///
    /// // Usage 1: Capture from a single owned device
    /// let dev: Device = pcap::Device::lookup()
    ///     .expect("device lookup failed")
    ///     .expect("no device available");
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
            self.check_err(raw::pcap_activate(self.handle.as_ptr()) == 0)?;
            Ok(mem::transmute(self))
        }
    }

    /// Set the read timeout for the Capture. By default, this is 0, so it will block
    /// indefinitely.
    pub fn timeout(self, ms: i32) -> Capture<Inactive> {
        unsafe { raw::pcap_set_timeout(self.handle.as_ptr(), ms) };
        self
    }

    /// Set the time stamp type to be used by a capture device.
    #[cfg(libpcap_1_2_1)]
    pub fn tstamp_type(self, tstamp_type: TimestampType) -> Capture<Inactive> {
        unsafe { raw::pcap_set_tstamp_type(self.handle.as_ptr(), tstamp_type as _) };
        self
    }

    /// Set promiscuous mode on or off. By default, this is off.
    pub fn promisc(self, to: bool) -> Capture<Inactive> {
        unsafe { raw::pcap_set_promisc(self.handle.as_ptr(), to as _) };
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
            raw::pcap_set_immediate_mode(self.handle.as_ptr(), to as _)
        };

        // In WinPcap we use `pcap_setmintocopy` as it does not have `pcap_set_immediate_mode`.
        #[cfg(all(windows, not(libpcap_1_5_0)))]
        unsafe {
            raw::pcap_setmintocopy(
                self.handle.as_ptr(),
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
        unsafe { raw::pcap_set_rfmon(self.handle.as_ptr(), to as _) };
        self
    }

    /// Set the buffer size for incoming packet data.
    ///
    /// The default is 1000000. This should always be larger than the snaplen.
    pub fn buffer_size(self, to: i32) -> Capture<Inactive> {
        unsafe { raw::pcap_set_buffer_size(self.handle.as_ptr(), to) };
        self
    }

    /// Set the time stamp precision returned in captures.
    #[cfg(libpcap_1_5_0)]
    pub fn precision(self, precision: Precision) -> Capture<Inactive> {
        unsafe { raw::pcap_set_tstamp_precision(self.handle.as_ptr(), precision as _) };
        self
    }

    /// Set the snaplen size (the maximum length of a packet captured into the buffer).
    /// Useful if you only want certain headers, but not the entire packet.
    ///
    /// The default is 65535.
    pub fn snaplen(self, to: i32) -> Capture<Inactive> {
        unsafe { raw::pcap_set_snaplen(self.handle.as_ptr(), to) };
        self
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
