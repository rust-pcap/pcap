#![allow(dead_code)]

use libc::{c_char, c_int, c_uchar, c_uint, FILE};

use crate::raw_common::{
    bpf_program, pcap_direction_t, pcap_dumper_t, pcap_if_t, pcap_pkthdr, pcap_send_queue,
    pcap_stat, pcap_t,
};
#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;

extern "C" {
    // [OBSOLETE] pub fn pcap_lookupdev(arg1: *mut c_char) -> *mut c_char;
    // pub fn pcap_lookupnet(arg1: *const c_char, arg2: *mut c_uint, arg3: *mut c_uint,
    //                       arg4: *mut c_char) -> c_int;
    pub fn pcap_create(arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t;
    pub fn pcap_set_snaplen(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub fn pcap_set_promisc(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    // pub fn pcap_can_set_rfmon(arg1: *mut pcap_t) -> c_int;
    pub fn pcap_set_timeout(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub fn pcap_set_buffer_size(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub fn pcap_activate(arg1: *mut pcap_t) -> c_int;
    // pub fn pcap_open_live(arg1: *const c_char, arg2: c_int, arg3: c_int, arg4: c_int,
    //                       arg5: *mut c_char) -> *mut pcap_t;
    pub fn pcap_open_dead(arg1: c_int, arg2: c_int) -> *mut pcap_t;
    pub fn pcap_open_offline(arg1: *const c_char, arg2: *mut c_char) -> *mut pcap_t;
    pub fn pcap_fopen_offline(arg1: *mut FILE, arg2: *mut c_char) -> *mut pcap_t;
    pub fn pcap_close(arg1: *mut pcap_t);
    // pub fn pcap_loop(arg1: *mut pcap_t, arg2: c_int,
    //                  arg3: pcap_handler, arg4: *mut c_uchar) -> c_int;
    // pub fn pcap_dispatch(arg1: *mut pcap_t, arg2: c_int, arg3: pcap_handler,
    //                      arg4: *mut c_uchar)-> c_int;
    // pub fn pcap_next(arg1: *mut pcap_t, arg2: *mut pcap_pkthdr) -> *const c_uchar;
    pub fn pcap_next_ex(
        arg1: *mut pcap_t,
        arg2: *mut *mut pcap_pkthdr,
        arg3: *mut *const c_uchar,
    ) -> c_int;
    // pub fn pcap_breakloop(arg1: *mut pcap_t);
    pub fn pcap_stats(arg1: *mut pcap_t, arg2: *mut pcap_stat) -> c_int;
    pub fn pcap_setfilter(arg1: *mut pcap_t, arg2: *mut bpf_program) -> c_int;
    pub fn pcap_setdirection(arg1: *mut pcap_t, arg2: pcap_direction_t) -> c_int;
    // pub fn pcap_getnonblock(arg1: *mut pcap_t, arg2: *mut c_char) -> c_int;
    pub fn pcap_setnonblock(arg1: *mut pcap_t, arg2: c_int, arg3: *mut c_char) -> c_int;
    pub fn pcap_sendpacket(arg1: *mut pcap_t, arg2: *const c_uchar, arg3: c_int) -> c_int;
    // pub fn pcap_statustostr(arg1: c_int) -> *const c_char;
    // pub fn pcap_strerror(arg1: c_int) -> *const c_char;
    pub fn pcap_geterr(arg1: *mut pcap_t) -> *mut c_char;
    // pub fn pcap_perror(arg1: *mut pcap_t, arg2: *mut c_char);
    pub fn pcap_compile(
        arg1: *mut pcap_t,
        arg2: *mut bpf_program,
        arg3: *const c_char,
        arg4: c_int,
        arg5: c_uint,
    ) -> c_int;
    // pub fn pcap_compile_nopcap(arg1: c_int, arg2: c_int, arg3: *mut bpf_program,
    //                            arg4: *const c_char, arg5: c_int, arg6: c_uint) -> c_int;
    pub fn pcap_freecode(arg1: *mut bpf_program);
    pub fn pcap_offline_filter(
        arg1: *const bpf_program,
        arg2: *const pcap_pkthdr,
        arg3: *const c_uchar,
    ) -> c_int;
    pub fn pcap_datalink(arg1: *mut pcap_t) -> c_int;
    // pub fn pcap_datalink_ext(arg1: *mut pcap_t) -> c_int;
    pub fn pcap_list_datalinks(arg1: *mut pcap_t, arg2: *mut *mut c_int) -> c_int;
    pub fn pcap_set_datalink(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub fn pcap_free_datalinks(arg1: *mut c_int);
    pub fn pcap_datalink_name_to_val(arg1: *const c_char) -> c_int;
    pub fn pcap_datalink_val_to_name(arg1: c_int) -> *const c_char;
    pub fn pcap_datalink_val_to_description(arg1: c_int) -> *const c_char;
    // pub fn pcap_snapshot(arg1: *mut pcap_t) -> c_int;
    // pub fn pcap_is_swapped(arg1: *mut pcap_t) -> c_int;
    pub fn pcap_major_version(arg1: *mut pcap_t) -> c_int;
    pub fn pcap_minor_version(arg1: *mut pcap_t) -> c_int;
    // pub fn pcap_file(arg1: *mut pcap_t) -> *mut FILE;
    pub fn pcap_fileno(arg1: *mut pcap_t) -> c_int;
    pub fn pcap_dump_open(arg1: *mut pcap_t, arg2: *const c_char) -> *mut pcap_dumper_t;
    pub fn pcap_dump_fopen(arg1: *mut pcap_t, fp: *mut FILE) -> *mut pcap_dumper_t;
    // pub fn pcap_dump_file(arg1: *mut pcap_dumper_t) -> *mut FILE;
    // pub fn pcap_dump_ftell(arg1: *mut pcap_dumper_t) -> c_long;
    pub fn pcap_dump_flush(arg1: *mut pcap_dumper_t) -> c_int;
    pub fn pcap_dump_close(arg1: *mut pcap_dumper_t);
    pub fn pcap_dump(arg1: *mut c_uchar, arg2: *const pcap_pkthdr, arg3: *const c_uchar);
    pub fn pcap_findalldevs(arg1: *mut *mut pcap_if_t, arg2: *mut c_char) -> c_int;
    pub fn pcap_freealldevs(arg1: *mut pcap_if_t);
    // pub fn pcap_lib_version() -> *const c_char;
    // pub fn bpf_image(arg1: *const bpf_insn, arg2: c_int) -> *mut c_char;
    // pub fn bpf_dump(arg1: *const bpf_program, arg2: c_int);
    pub fn pcap_get_selectable_fd(arg1: *mut pcap_t) -> c_int;
}

#[cfg(libpcap_1_2_1)]
extern "C" {
    // pub fn pcap_free_tstamp_types(arg1: *mut c_int) -> ();
    // pub fn pcap_list_tstamp_types(arg1: *mut pcap_t, arg2: *mut *mut c_int) -> c_int;
    // pub fn pcap_tstamp_type_name_to_val(arg1: *const c_char) -> c_int;
    // pub fn pcap_tstamp_type_val_to_description(arg1: c_int) -> *const c_char;
    // pub fn pcap_tstamp_type_val_to_name(arg1: c_int) -> *const c_char;
    pub fn pcap_set_tstamp_type(arg1: *mut pcap_t, arg2: c_int) -> c_int;
}

#[cfg(libpcap_1_5_0)]
extern "C" {
    pub fn pcap_fopen_offline_with_tstamp_precision(
        arg1: *mut FILE,
        arg2: c_uint,
        arg3: *mut c_char,
    ) -> *mut pcap_t;
    // pub fn pcap_get_tstamp_precision(arg1: *mut pcap_t) -> c_int;
    pub fn pcap_open_dead_with_tstamp_precision(
        arg1: c_int,
        arg2: c_int,
        arg3: c_uint,
    ) -> *mut pcap_t;
    pub fn pcap_open_offline_with_tstamp_precision(
        arg1: *const c_char,
        arg2: c_uint,
        arg3: *mut c_char,
    ) -> *mut pcap_t;
    pub fn pcap_set_immediate_mode(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub fn pcap_set_tstamp_precision(arg1: *mut pcap_t, arg2: c_int) -> c_int;
}

#[cfg(libpcap_1_7_2)]
extern "C" {
    pub fn pcap_dump_open_append(arg1: *mut pcap_t, arg2: *const c_char) -> *mut pcap_dumper_t;
}

#[cfg(libpcap_1_9_0)]
extern "C" {
    // pcap_bufsize
    // pcap_createsrcstr
    // pcap_dump_ftell64
    // pcap_findalldevs_ex
    // pcap_get_required_select_timeout
    // pcap_open
    // pcap_parsesrcstr
    // pcap_remoteact_accept
    // pcap_remoteact_cleanup
    // pcap_remoteact_close
    // pcap_remoteact_list
    // pcap_set_protocol_linux
    // pcap_setsampling
}

#[cfg(libpcap_1_9_1)]
extern "C" {
    // pcap_datalink_val_to_description_or_dlt
}

#[cfg(windows)]
#[link(name = "wpcap")]
extern "C" {
    pub fn pcap_setmintocopy(arg1: *mut pcap_t, arg2: c_int) -> c_int;
    pub fn pcap_getevent(p: *mut pcap_t) -> HANDLE;
    pub fn pcap_sendqueue_alloc(memsize: c_uint) -> *mut pcap_send_queue;
    pub fn pcap_sendqueue_destroy(queue: *mut pcap_send_queue);
    pub fn pcap_sendqueue_queue(
        queue: *mut pcap_send_queue,
        pkt_header: *const pcap_pkthdr,
        pkt_data: *const c_uchar,
    ) -> c_int;
    pub fn pcap_sendqueue_transmit(
        p: *mut pcap_t,
        queue: *mut pcap_send_queue,
        sync: c_int,
    ) -> c_uint;
}

#[cfg(not(windows))]
#[link(name = "pcap")]
extern "C" {
    // pub fn pcap_inject(arg1: *mut pcap_t, arg2: *const c_void, arg3: size_t) -> c_int;
    pub fn pcap_set_rfmon(arg1: *mut pcap_t, arg2: c_int) -> c_int;
}
