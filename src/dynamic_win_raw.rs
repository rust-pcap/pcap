#![allow(dead_code)]

use std::env;
use crate::raw_common::{
    bpf_program, pcap_direction_t, pcap_dumper_t, pcap_if_t, pcap_pkthdr, pcap_send_queue,
    pcap_stat, pcap_t,
};
use libc::{c_char, c_int, c_uchar, c_uint, FILE};
use libloading::Library;
use std::path::PathBuf;
use once_cell::sync::Lazy;
use windows_sys::Win32::Foundation::HANDLE;

type PcapCreate = unsafe extern "C" fn(arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t;
type PcapSetSnaplen = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
type PcapSetPromisc = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
type PcapSetTimeout = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
type PcapSetBufferSize = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
type PcapActivate = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;
type PcapOpenDead = unsafe extern "C" fn(arg1: c_int, arg2: c_int) -> *mut pcap_t;
type PcapOpenOffline = unsafe extern "C" fn(arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t;
type PcapFopenOffline = unsafe extern "C" fn(arg1: *mut FILE, arg2: *mut c_char) -> *mut pcap_t;
type PcapClose = unsafe extern "C" fn(arg1: *mut pcap_t);
type PcapNextEx = unsafe extern "C" fn(
    arg1: *mut pcap_t,
    arg2: *mut *mut pcap_pkthdr,
    arg3: *mut *const c_uchar,
) -> c_int;
type PcapStats = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *mut pcap_stat) -> c_int;
type PcapSetfilter = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *mut bpf_program) -> c_int;
type PcapSetdirection = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: pcap_direction_t) -> c_int;
type PcapSetnonblock =
    unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int, arg3: *mut c_char) -> c_int;
type PcapSendpacket =
    unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *const c_uchar, arg3: c_int) -> c_int;
type PcapGeterr = unsafe extern "C" fn(arg1: *mut pcap_t) -> *mut c_char;
type PcapCompile = unsafe extern "C" fn(
    arg1: *mut pcap_t,
    arg2: *mut bpf_program,
    arg3: *const c_char,
    arg4: c_int,
    arg5: c_uint,
) -> c_int;
type PcapFreecode = unsafe extern "C" fn(arg1: *mut bpf_program);
type PcapOfflineFilter = unsafe extern "C" fn(
    arg1: *const bpf_program,
    arg2: *const pcap_pkthdr,
    arg3: *const c_uchar,
) -> c_int;
type PcapDatalink = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;
type PcapListDatalinks = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *mut *mut c_int) -> c_int;
type PcapSetDatalink = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
type PcapFreeDatalinks = unsafe extern "C" fn(arg1: *mut c_int);
type PcapDatalinkNameToVal = unsafe extern "C" fn(arg1: *const c_char) -> c_int;
type PcapDatalinkValToName = unsafe extern "C" fn(arg1: c_int) -> *const c_char;
type PcapDatalinkValToDescription = unsafe extern "C" fn(arg1: c_int) -> *const c_char;
type PcapMajorVersion = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;
type PcapMinorVersion = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;
type PcapFileno = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;
type PcapDumpOpen =
    unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *const c_char) -> *mut pcap_dumper_t;
type PcapDumpFopen = unsafe extern "C" fn(arg1: *mut pcap_t, fp: *mut FILE) -> *mut pcap_dumper_t;
type PcapDumpFlush = unsafe extern "C" fn(arg1: *mut pcap_dumper_t) -> c_int;
type PcapDumpClose = unsafe extern "C" fn(arg1: *mut pcap_dumper_t);
type PcapDump =
    unsafe extern "C" fn(arg1: *mut c_uchar, arg2: *const pcap_pkthdr, arg3: *const c_uchar);
type PcapFindalldevs = unsafe extern "C" fn(arg1: *mut *mut pcap_if_t, arg2: *mut c_char) -> c_int;
type PcapFreealldevs = unsafe extern "C" fn(arg1: *mut pcap_if_t);
type PcapGetSelectableFd = unsafe extern "C" fn(arg1: *mut pcap_t) -> c_int;
type PcapSetTstampType = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
type PcapFopenOfflineWithTstampPrecision =
    unsafe extern "C" fn(arg1: *mut FILE, arg2: c_uint, arg3: *mut c_char) -> *mut pcap_t;
type PcapOpenDeadWithTstampPrecision =
    unsafe extern "C" fn(arg1: c_int, arg2: c_int, arg3: c_uint) -> *mut pcap_t;
type PcapOpenOfflineWithTstampPrecision =
    unsafe extern "C" fn(arg1: *const c_char, arg2: c_uint, arg3: *mut c_char) -> *mut pcap_t;
type PcapSetImmediateMode = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
type PcapSetTstampPrecision = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
type PcapDumpOpenAppend =
    unsafe extern "C" fn(arg1: *mut pcap_t, arg2: *const c_char) -> *mut pcap_dumper_t;
type PcapSetmintocopy = unsafe extern "C" fn(arg1: *mut pcap_t, arg2: c_int) -> c_int;
type PcapGetEvent = unsafe extern "C" fn(p: *mut pcap_t) -> HANDLE;
type PcapSendqueueAlloc = unsafe extern "C" fn(memsize: c_uint) -> *mut pcap_send_queue;
type PcapSendqueueDestroy = unsafe extern "C" fn(queue: *mut pcap_send_queue);
type PcapSendqueueQueue = unsafe extern "C" fn(
    queue: *mut pcap_send_queue,
    pkt_header: *const pcap_pkthdr,
    pkt_data: *const c_uchar,
) -> c_int;
type PcapSendqueueTransmit =
    unsafe extern "C" fn(p: *mut pcap_t, queue: *mut pcap_send_queue, sync: c_int) -> c_uint;

static mut LIBRARY: Lazy<Library> = Lazy::new(|| {
    unsafe { load_library() }
});

unsafe fn load_library() -> Library {
    let mut libfile = PathBuf::from("wpcap.dll");

    let libdirpath = if let Ok(libdir) = env::var("LIBPCAP_LIBDIR") {
        Some(PathBuf::from(&libdir))
    } else {
        None
    };

    if let Some(libdir) = libdirpath {
        libfile = libdir.join(libfile);
    }

    Library::new(libfile).unwrap()
}

pub unsafe fn pcap_create(arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t {
    let func = LIBRARY.get::<PcapCreate>(b"pcap_create").unwrap();
    func(arg1, arg2)
}
pub unsafe fn pcap_set_snaplen(arg1: *mut pcap_t, arg2: c_int) -> c_int {
    let func = LIBRARY.get::<PcapSetSnaplen>(b"pcap_set_snaplen").unwrap();
    func(arg1, arg2)
}
pub unsafe fn pcap_set_promisc(arg1: *mut pcap_t, arg2: c_int) -> c_int {
    let func = LIBRARY.get::<PcapSetPromisc>(b"pcap_set_promisc").unwrap();
    func(arg1, arg2)
}
pub unsafe fn pcap_set_timeout(arg1: *mut pcap_t, arg2: c_int) -> c_int {
    let func = LIBRARY.get::<PcapSetTimeout>(b"pcap_set_timeout").unwrap();
    func(arg1, arg2)
}
pub unsafe fn pcap_set_buffer_size(arg1: *mut pcap_t, arg2: c_int) -> c_int {
    let func = LIBRARY
        .get::<PcapSetBufferSize>(b"pcap_set_buffer_size")
        .unwrap();
    func(arg1, arg2)
}
pub unsafe fn pcap_activate(arg1: *mut pcap_t) -> c_int {
    let func = LIBRARY.get::<PcapActivate>(b"pcap_activate").unwrap();
    func(arg1)
}
pub unsafe fn pcap_open_dead(arg1: c_int, arg2: c_int) -> *mut pcap_t {
    let func = LIBRARY.get::<PcapOpenDead>(b"pcap_open_dead").unwrap();
    func(arg1, arg2)
}
pub unsafe fn pcap_open_offline(arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t {
    let func = LIBRARY.get::<PcapOpenOffline>(b"pcap_open_offline").unwrap();
    func(arg1, arg2)
}
pub unsafe fn pcap_fopen_offline(arg1: *mut FILE, arg2: *mut c_char) -> *mut pcap_t {
    let func = LIBRARY.get::<PcapFopenOffline>(b"pcap_fopen_offline").unwrap();
    func(arg1, arg2)
}
pub unsafe fn pcap_close(arg1: *mut pcap_t) {
    let func = LIBRARY.get::<PcapClose>(b"pcap_close").unwrap();
    func(arg1)
}
pub unsafe fn pcap_next_ex(
    arg1: *mut pcap_t,
    arg2: *mut *mut pcap_pkthdr,
    arg3: *mut *const c_uchar,
) -> c_int {
    let func = LIBRARY.get::<PcapNextEx>(b"pcap_next_ex").unwrap();
    func(arg1, arg2, arg3)
}
pub unsafe fn pcap_stats(arg1: *mut pcap_t, arg2: *mut pcap_stat) -> c_int {
    let func = LIBRARY.get::<PcapStats>(b"pcap_stats").unwrap();
    func(arg1, arg2)
}
pub unsafe fn pcap_setfilter(arg1: *mut pcap_t, arg2: *mut bpf_program) -> c_int {
    let func = LIBRARY.get::<PcapSetfilter>(b"pcap_setfilter").unwrap();
    func(arg1, arg2)
}
pub unsafe fn pcap_setdirection(arg1: *mut pcap_t, arg2: pcap_direction_t) -> c_int {
    let func = LIBRARY.get::<PcapSetdirection>(b"pcap_setdirection").unwrap();
    func(arg1, arg2)
}
pub unsafe fn pcap_setnonblock(arg1: *mut pcap_t, arg2: c_int, arg3: *mut c_char) -> c_int {
    let func = LIBRARY.get::<PcapSetnonblock>(b"pcap_setnonblock").unwrap();
    func(arg1, arg2, arg3)
}
pub unsafe fn pcap_sendpacket(arg1: *mut pcap_t, arg2: *const c_uchar, arg3: c_int) -> c_int {
    let func = LIBRARY.get::<PcapSendpacket>(b"pcap_sendpacket").unwrap();
    func(arg1, arg2, arg3)
}
pub unsafe fn pcap_geterr(arg1: *mut pcap_t) -> *mut c_char {
    let func = LIBRARY.get::<PcapGeterr>(b"pcap_geterr").unwrap();
    func(arg1)
}
pub unsafe fn pcap_compile(
    arg1: *mut pcap_t,
    arg2: *mut bpf_program,
    arg3: *const c_char,
    arg4: c_int,
    arg5: c_uint,
) -> c_int {
    let func = LIBRARY.get::<PcapCompile>(b"pcap_compile").unwrap();
    func(arg1, arg2, arg3, arg4, arg5)
}
pub unsafe fn pcap_freecode(arg1: *mut bpf_program) {
    let func = LIBRARY.get::<PcapFreecode>(b"pcap_freecode").unwrap();
    func(arg1)
}
pub unsafe fn pcap_offline_filter(
    arg1: *const bpf_program,
    arg2: *const pcap_pkthdr,
    arg3: *const c_uchar,
) -> c_int {
    let func = LIBRARY
        .get::<PcapOfflineFilter>(b"pcap_offline_filter")
        .unwrap();
    func(arg1, arg2, arg3)
}
pub unsafe fn pcap_datalink(arg1: *mut pcap_t) -> c_int {
    let func = LIBRARY.get::<PcapDatalink>(b"pcap_datalink").unwrap();
    func(arg1)
}
pub unsafe fn pcap_list_datalinks(arg1: *mut pcap_t, arg2: *mut *mut c_int) -> c_int {
    let func = LIBRARY
        .get::<PcapListDatalinks>(b"pcap_list_datalinks")
        .unwrap();
    func(arg1, arg2)
}
pub unsafe fn pcap_set_datalink(arg1: *mut pcap_t, arg2: c_int) -> c_int {
    let func = LIBRARY.get::<PcapSetDatalink>(b"pcap_set_datalink").unwrap();
    func(arg1, arg2)
}
pub unsafe fn pcap_free_datalinks(arg1: *mut c_int) {
    let func = LIBRARY
        .get::<PcapFreeDatalinks>(b"pcap_free_datalinks")
        .unwrap();
    func(arg1)
}
pub unsafe fn pcap_datalink_name_to_val(arg1: *const c_char) -> c_int {
    let func = LIBRARY
        .get::<PcapDatalinkNameToVal>(b"pcap_datalink_name_to_val")
        .unwrap();
    func(arg1)
}
pub unsafe fn pcap_datalink_val_to_name(arg1: c_int) -> *const c_char {
    let func = LIBRARY
        .get::<PcapDatalinkValToName>(b"pcap_datalink_val_to_name")
        .unwrap();
    func(arg1)
}
pub unsafe fn pcap_datalink_val_to_description(arg1: c_int) -> *const c_char {
    let func = LIBRARY
        .get::<PcapDatalinkValToDescription>(b"pcap_datalink_val_to_description")
        .unwrap();
    func(arg1)
}
pub unsafe fn pcap_major_version(arg1: *mut pcap_t) -> c_int {
    let func = LIBRARY.get::<PcapMajorVersion>(b"pcap_major_version").unwrap();
    func(arg1)
}
pub unsafe fn pcap_minor_version(arg1: *mut pcap_t) -> c_int {
    let func = LIBRARY.get::<PcapMinorVersion>(b"pcap_minor_version").unwrap();
    func(arg1)
}
pub unsafe fn pcap_fileno(arg1: *mut pcap_t) -> c_int {
    let func = LIBRARY.get::<PcapFileno>(b"pcap_fileno").unwrap();
    func(arg1)
}
pub unsafe fn pcap_dump_open(arg1: *mut pcap_t, arg2: *const c_char) -> *mut pcap_dumper_t {
    let func = LIBRARY.get::<PcapDumpOpen>(b"pcap_dump_open").unwrap();
    func(arg1, arg2)
}
pub unsafe fn pcap_dump_fopen(arg1: *mut pcap_t, fp: *mut FILE) -> *mut pcap_dumper_t {
    let func = LIBRARY.get::<PcapDumpFopen>(b"pcap_dump_fopen").unwrap();
    func(arg1, fp)
}
pub unsafe fn pcap_dump_flush(arg1: *mut pcap_dumper_t) -> c_int {
    let func = LIBRARY.get::<PcapDumpFlush>(b"pcap_dump_flush").unwrap();
    func(arg1)
}
pub unsafe fn pcap_dump_close(arg1: *mut pcap_dumper_t) {
    let func = LIBRARY.get::<PcapDumpClose>(b"pcap_dump_close").unwrap();
    func(arg1)
}
pub unsafe fn pcap_dump(arg1: *mut c_uchar, arg2: *const pcap_pkthdr, arg3: *const c_uchar) {
    let func = LIBRARY.get::<PcapDump>(b"pcap_dump").unwrap();
    func(arg1, arg2, arg3)
}
pub unsafe fn pcap_findalldevs(arg1: *mut *mut pcap_if_t, arg2: *mut c_char) -> c_int {
    let func = LIBRARY.get::<PcapFindalldevs>(b"pcap_findalldevs").unwrap();
    func(arg1, arg2)
}
pub unsafe fn pcap_freealldevs(arg1: *mut pcap_if_t) {
    let func = LIBRARY.get::<PcapFreealldevs>(b"pcap_freealldevs").unwrap();
    func(arg1)
}
pub unsafe fn pcap_get_selectable_fd(arg1: *mut pcap_t) -> c_int {
    let func = LIBRARY
        .get::<PcapGetSelectableFd>(b"pcap_get_selectable_fd")
        .unwrap();
    func(arg1)
}

#[cfg(libpcap_1_2_1)]
pub fn pcap_set_tstamp_type(arg1: *mut pcap_t, arg2: c_int) -> c_int {
    let func = LIBRARY
        .get::<PcapSetTstampType>(b"pcap_set_tstamp_type")
        .unwrap();
    func(arg1, arg2)
}

#[cfg(libpcap_1_5_0)]
pub fn pcap_fopen_offline_with_tstamp_precision(
    arg1: *mut FILE,
    arg2: c_uint,
    arg3: *mut c_char,
) -> *mut pcap_t {
    let func = LIBRARY
        .get::<PcapFopenOfflineWithTstampPrecision>(b"pcap_fopen_offline_with_tstamp_precision")
        .unwrap();
    func(arg1, arg2, arg3)
}
#[cfg(libpcap_1_5_0)]
pub fn pcap_open_dead_with_tstamp_precision(arg1: c_int, arg2: c_int, arg3: c_uint) -> *mut pcap_t {
    let func = LIBRARY
        .get::<PcapOpenDeadWithTstampPrecision>(b"pcap_open_dead_with_tstamp_precision")
        .unwrap();
    func(arg1, arg2, arg3)
}
#[cfg(libpcap_1_5_0)]
pub fn pcap_open_offline_with_tstamp_precision(
    arg1: *const c_char,
    arg2: c_uint,
    arg3: *mut c_char,
) -> *mut pcap_t {
    let func = LIBRARY
        .get::<PcapOpenOfflineWithTstampPrecision>(b"pcap_open_offline_with_tstamp_precision")
        .unwrap();
    func(arg1, arg2, arg3)
}
#[cfg(libpcap_1_5_0)]
pub fn pcap_set_immediate_mode(arg1: *mut pcap_t, arg2: c_int) -> c_int {
    let func = LIBRARY
        .get::<PcapSetImmediateMode>(b"pcap_set_immediate_mode")
        .unwrap();
    func(arg1, arg2)
}
#[cfg(libpcap_1_5_0)]
pub fn pcap_set_tstamp_precision(arg1: *mut pcap_t, arg2: c_int) -> c_int {
    let func = LIBRARY
        .get::<PcapSetTstampPrecision>(b"pcap_set_tstamp_precision")
        .unwrap();
    func(arg1, arg2)
}

#[cfg(libpcap_1_7_2)]
pub fn pcap_dump_open_append(arg1: *mut pcap_t, arg2: *const c_char) -> *mut pcap_dumper_t {
    let func = LIBRARY
        .get::<PcapDumpOpenAppend>(b"pcap_dump_open_append")
        .unwrap();
    func(arg1, arg2)
}

pub unsafe fn pcap_setmintocopy(arg1: *mut pcap_t, arg2: c_int) -> c_int {
    let func = LIBRARY.get::<PcapSetmintocopy>(b"pcap_setmintocopy").unwrap();
    func(arg1, arg2)
}
pub unsafe fn pcap_getevent(p: *mut pcap_t) -> HANDLE {
    let func = LIBRARY.get::<PcapGetEvent>(b"pcap_getevent").unwrap();
    func(p)
}
pub unsafe fn pcap_sendqueue_alloc(memsize: c_uint) -> *mut pcap_send_queue {
    let func = LIBRARY
        .get::<PcapSendqueueAlloc>(b"pcap_sendqueue_alloc")
        .unwrap();
    func(memsize)
}
pub unsafe fn pcap_sendqueue_destroy(queue: *mut pcap_send_queue) {
    let func = LIBRARY
        .get::<PcapSendqueueDestroy>(b"pcap_sendqueue_destroy")
        .unwrap();
    func(queue)
}
pub unsafe fn pcap_sendqueue_queue(
    queue: *mut pcap_send_queue,
    pkt_header: *const pcap_pkthdr,
    pkt_data: *const c_uchar,
) -> c_int {
    let func = LIBRARY
        .get::<PcapSendqueueQueue>(b"pcap_sendqueue_queue")
        .unwrap();
    func(queue, pkt_header, pkt_data)
}
pub unsafe fn pcap_sendqueue_transmit(
    p: *mut pcap_t,
    queue: *mut pcap_send_queue,
    sync: c_int,
) -> c_uint {
    let func = LIBRARY
        .get::<PcapSendqueueTransmit>(b"pcap_sendqueue_transmit")
        .unwrap();
    func(p, queue, sync)
}
