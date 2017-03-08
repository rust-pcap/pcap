use std::env;

fn main() {
    if let Ok(libdir) = env::var("PCAP_LIBDIR") {
        println!("cargo:rustc-link-search={}", libdir);
    }
}
