use std::{fmt, mem::MaybeUninit, ops::Deref, ptr};

use crate::raw;

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

impl Deref for Packet<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.data
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
/// Represents a packet header provided by pcap, including the timeval, caplen and len.
///
/// On a 32-bit target whose C library uses a 64-bit `time_t`, `ts` holds libpcap's timestamp
/// converted to `libc::timeval`. A time after January 2038 does not fit.
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

impl PacketHeader {
    /// Returns the header that libpcap handed out, borrowing it when the loaded libpcap lays
    /// headers out as `PacketHeader` does and converting it into `buf` when it does not.
    ///
    /// # Safety
    ///
    /// `header` must point to a header filled in by libpcap that remains valid while the returned
    /// reference is in use.
    #[inline]
    pub(crate) unsafe fn from_raw(
        header: *const raw::pcap_pkthdr,
        buf: &mut MaybeUninit<PacketHeader>,
    ) -> &PacketHeader {
        unsafe { PacketHeader::borrow_or_read(header, layout(), buf) }
    }

    #[inline]
    unsafe fn borrow_or_read(
        header: *const raw::pcap_pkthdr,
        layout: Layout,
        buf: &mut MaybeUninit<PacketHeader>,
    ) -> &PacketHeader {
        match layout {
            Layout::Native => unsafe { &*header.cast::<PacketHeader>() },
            layout => buf.write(unsafe { PacketHeader::read(header, layout) }),
        }
    }

    /// Returns a pointer to the header laid out as the loaded libpcap reads it, for a call that
    /// takes one: the header itself when the layouts match, and a copy converted into `buf` when
    /// they do not. The pointer is valid as long as both `self` and `buf` are.
    #[inline]
    pub(crate) fn as_raw(&self, buf: &mut MaybeUninit<RawHeader>) -> *const raw::pcap_pkthdr {
        self.borrow_or_write(layout(), buf)
    }

    #[inline]
    fn borrow_or_write(
        &self,
        layout: Layout,
        buf: &mut MaybeUninit<RawHeader>,
    ) -> *const raw::pcap_pkthdr {
        match layout {
            Layout::Native => (self as *const PacketHeader).cast(),
            layout => buf.write(self.write(layout)).as_ptr(),
        }
    }

    // `time_t` and `suseconds_t` are 32 or 64 bits wide depending on the target.
    #[allow(clippy::unnecessary_cast)]
    unsafe fn read(header: *const raw::pcap_pkthdr, layout: Layout) -> PacketHeader {
        match layout {
            Layout::Native => {
                let header = unsafe { ptr::read_unaligned(header) };
                PacketHeader {
                    ts: header.ts,
                    caplen: header.caplen,
                    len: header.len,
                }
            }
            Layout::Narrow => {
                let header = unsafe { ptr::read_unaligned(header.cast::<NarrowPkthdr>()) };
                PacketHeader {
                    ts: libc::timeval {
                        tv_sec: header.tv_sec as _,
                        tv_usec: header.tv_usec as _,
                    },
                    caplen: header.caplen,
                    len: header.len,
                }
            }
            Layout::Wide => {
                let header = unsafe { ptr::read_unaligned(header.cast::<WidePkthdr>()) };
                PacketHeader {
                    ts: libc::timeval {
                        tv_sec: header.tv_sec as _,
                        tv_usec: header.tv_usec as _,
                    },
                    caplen: header.caplen,
                    len: header.len,
                }
            }
        }
    }

    #[allow(clippy::unnecessary_cast)]
    fn write(self, layout: Layout) -> RawHeader {
        match layout {
            Layout::Native => RawHeader::Native(raw::pcap_pkthdr {
                ts: self.ts,
                caplen: self.caplen,
                len: self.len,
            }),
            Layout::Narrow => RawHeader::Narrow(NarrowPkthdr {
                tv_sec: self.ts.tv_sec as _,
                tv_usec: self.ts.tv_usec as _,
                caplen: self.caplen,
                len: self.len,
            }),
            Layout::Wide => RawHeader::Wide(WidePkthdr {
                tv_sec: self.ts.tv_sec as _,
                tv_usec: self.ts.tv_usec as _,
                caplen: self.caplen,
                len: self.len,
            }),
        }
    }
}

impl fmt::Debug for PacketHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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

/// How the loaded libpcap lays out `struct pcap_pkthdr`.
///
/// `struct timeval` holds two `long`s on most targets, and `libc::timeval` follows. A 32-bit
/// target is the exception: musl 1.2 and later, and glibc built with `_TIME_BITS=64`, widen both
/// fields to 64 bits, while `libc::timeval` keeps them at 32 by default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// Only a 32-bit target asks libpcap for the layout, so elsewhere nothing constructs `Narrow` or
// `Wide`.
#[cfg_attr(not(any(test, target_pointer_width = "32")), allow(dead_code))]
enum Layout {
    /// The layout of `raw::pcap_pkthdr`.
    Native,
    /// `ts` holds two 32-bit fields, where `libc::timeval` is wider.
    Narrow,
    /// `ts` holds two 64-bit fields, where `libc::timeval` is narrower.
    Wide,
}

/// A header whose `ts` holds two 32-bit fields: 16 bytes, with `caplen` at offset 8.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct NarrowPkthdr {
    tv_sec: i32,
    tv_usec: i32,
    caplen: u32,
    len: u32,
}

/// A header whose `ts` holds two 64-bit fields: 24 bytes, with `caplen` at offset 16.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct WidePkthdr {
    tv_sec: i64,
    tv_usec: i64,
    caplen: u32,
    len: u32,
}

/// A header laid out for the loaded libpcap.
pub(crate) enum RawHeader {
    Native(raw::pcap_pkthdr),
    Narrow(NarrowPkthdr),
    Wide(WidePkthdr),
}

impl RawHeader {
    pub(crate) fn as_ptr(&self) -> *const raw::pcap_pkthdr {
        match self {
            RawHeader::Native(header) => header,
            RawHeader::Narrow(header) => (header as *const NarrowPkthdr).cast(),
            RawHeader::Wide(header) => (header as *const WidePkthdr).cast(),
        }
    }
}

/// On a 32-bit target the C library may use a 64-bit `time_t`, so libpcap's `struct timeval` can
/// differ from `libc::timeval` and the layout has to be asked of libpcap. Elsewhere the crate takes
/// the layout to be that of `raw::pcap_pkthdr`.
#[cfg(not(target_pointer_width = "32"))]
#[inline]
fn layout() -> Layout {
    Layout::Native
}

#[cfg(target_pointer_width = "32")]
#[inline]
fn layout() -> Layout {
    // The FFI is mocked under test, and the mocks hand out headers laid out as `raw::pcap_pkthdr`.
    #[cfg(test)]
    {
        Layout::Native
    }
    #[cfg(not(test))]
    {
        static LAYOUT: std::sync::OnceLock<Layout> = std::sync::OnceLock::new();
        *LAYOUT.get_or_init(probe)
    }
}

/// Asks the loaded libpcap where it reads `len`. A filter of two instructions, `ld len` and
/// `ret a`, returns the packet length, and the header passed with it holds 16 where a 16-byte
/// header keeps `len` and 24 where a 24-byte header does.
#[cfg(any(test, target_pointer_width = "32"))]
fn probe() -> Layout {
    const LD_LEN: u16 = 0x80; // BPF_LD | BPF_W | BPF_LEN
    const RET_A: u16 = 0x16; // BPF_RET | BPF_A

    #[repr(C, align(8))]
    struct Header([u32; 6]);

    // Words 3 and 5 are `len` in a 16-byte and a 24-byte header. `caplen` is zero in both, so
    // libpcap is given no packet data to read.
    let header = Header([0, 0, 0, 16, 0, 24]);
    let mut insns = [
        raw::bpf_insn {
            code: LD_LEN,
            jt: 0,
            jf: 0,
            k: 0,
        },
        raw::bpf_insn {
            code: RET_A,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ];
    let program = raw::bpf_program {
        bf_len: insns.len() as _,
        bf_insns: insns.as_mut_ptr(),
    };
    let data = [0u8];

    let len =
        unsafe { raw::pcap_offline_filter(&program, header.0.as_ptr().cast(), data.as_ptr()) };
    layout_for(len, std::mem::size_of::<raw::pcap_pkthdr>())
}

/// The layout of a header `len` bytes long, where `raw::pcap_pkthdr` is `native` bytes long.
#[cfg(any(test, target_pointer_width = "32"))]
fn layout_for(len: libc::c_int, native: usize) -> Layout {
    match (len, native) {
        (16, 24) => Layout::Narrow,
        (24, 16) => Layout::Wide,
        // Either the sizes match, or the answer is neither size.
        _ => Layout::Native,
    }
}

#[cfg(test)]
mod tests {
    use std::{mem, slice};

    use crate::raw::{self, testmod::RAWMTX};

    use super::*;

    static HEADER: PacketHeader = PacketHeader {
        ts: libc::timeval {
            tv_sec: 5,
            tv_usec: 50,
        },
        caplen: 5,
        len: 9,
    };

    #[test]
    fn test_packet_header_size() {
        use std::mem::size_of;
        assert_eq!(size_of::<PacketHeader>(), size_of::<raw::pcap_pkthdr>());
    }

    #[test]
    fn test_packet_header_clone() {
        // For code coverag purposes.
        #[allow(clippy::clone_on_copy)]
        let header_clone = HEADER.clone();
        assert_eq!(header_clone, HEADER);
    }

    #[test]
    fn test_packet_header_display() {
        assert!(!format!("{HEADER:?}").is_empty());
    }

    #[test]
    fn test_layout_sizes() {
        assert_eq!(mem::size_of::<NarrowPkthdr>(), 16);
        assert_eq!(mem::offset_of!(NarrowPkthdr, caplen), 8);
        assert_eq!(mem::size_of::<WidePkthdr>(), 24);
        assert_eq!(mem::offset_of!(WidePkthdr, caplen), 16);
    }

    #[test]
    fn test_read_foreign_layouts() {
        let narrow = NarrowPkthdr {
            tv_sec: 5,
            tv_usec: 50,
            caplen: 5,
            len: 9,
        };
        let wide = WidePkthdr {
            tv_sec: 5,
            tv_usec: 50,
            caplen: 5,
            len: 9,
        };

        let header =
            unsafe { PacketHeader::read((&narrow as *const NarrowPkthdr).cast(), Layout::Narrow) };
        assert_eq!(header, HEADER);
        let header =
            unsafe { PacketHeader::read((&wide as *const WidePkthdr).cast(), Layout::Wide) };
        assert_eq!(header, HEADER);
    }

    #[test]
    fn test_read_write_every_layout() {
        for layout in [Layout::Native, Layout::Narrow, Layout::Wide] {
            let raw = HEADER.write(layout);
            let header = unsafe { PacketHeader::read(raw.as_ptr(), layout) };
            assert_eq!(header, HEADER, "{layout:?}");
        }
    }

    #[test]
    fn test_borrow_or_read() {
        let native = HEADER.write(Layout::Native);
        let mut buf = MaybeUninit::<PacketHeader>::uninit();
        let header =
            unsafe { PacketHeader::borrow_or_read(native.as_ptr(), Layout::Native, &mut buf) };
        assert!(ptr::eq(header, native.as_ptr().cast()));

        let wide = HEADER.write(Layout::Wide);
        let mut buf = MaybeUninit::<PacketHeader>::uninit();
        let converted = buf.as_ptr();
        let header = unsafe { PacketHeader::borrow_or_read(wide.as_ptr(), Layout::Wide, &mut buf) };
        assert!(ptr::eq(header, converted));
        assert_eq!(*header, HEADER);
    }

    #[test]
    fn test_borrow_or_write() {
        let mut buf = MaybeUninit::<RawHeader>::uninit();
        let native = HEADER.borrow_or_write(Layout::Native, &mut buf);
        assert!(ptr::eq(native, (&HEADER as *const PacketHeader).cast()));

        let wide = HEADER.borrow_or_write(Layout::Wide, &mut buf);
        assert!(ptr::eq(wide, unsafe { buf.assume_init_ref() }.as_ptr()));
        assert_eq!(unsafe { PacketHeader::read(wide, Layout::Wide) }, HEADER);
    }

    #[test]
    fn test_layout_for() {
        assert_eq!(layout_for(16, 24), Layout::Narrow);
        assert_eq!(layout_for(24, 16), Layout::Wide);
        assert_eq!(layout_for(16, 16), Layout::Native);
        assert_eq!(layout_for(24, 24), Layout::Native);
        assert_eq!(layout_for(0, 24), Layout::Native);
    }

    #[test]
    fn test_probe() {
        let _m = RAWMTX.lock();

        for answer in [16, 24] {
            let ctx = raw::pcap_offline_filter_context();
            ctx.checkpoint();
            ctx.expect()
                .withf_st(|program, header, _| unsafe {
                    let insns =
                        slice::from_raw_parts((**program).bf_insns, (**program).bf_len as _);
                    let words = slice::from_raw_parts(header.cast::<u32>(), 6);
                    insns.len() == 2
                        && insns[0].code == 0x80
                        && insns[1].code == 0x16
                        && words == [0, 0, 0, 16, 0, 24]
                })
                .return_once_st(move |_, _, _| answer);

            assert_eq!(
                probe(),
                layout_for(answer, mem::size_of::<raw::pcap_pkthdr>())
            );
        }
    }
}
