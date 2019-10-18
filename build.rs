use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    if pkg_config::Config::new().cargo_metadata(true).probe("libpcap").is_ok() {
        println!("cargo:rustc-cfg=has_pkg_config");
        return
    }

    println!("cargo:rerun-if-env-changed=PCAP_LIBDIR");
    if let Ok(libdir) = env::var("PCAP_LIBDIR") {
        println!("cargo:rustc-link-search=native={}", libdir);
    }
}
