///! nfbpf_compile works the same way as the small tool bundled with iptables:
///! it compiles a pcap expression in to a BPF filter, then serializes it using
///! a simple, safe encoding.
///!

extern crate pcap;

use pcap::{Capture, Linktype};

use std::env;
use std::process;


fn main() {
    let (layertype, prog) = match env::args().len() {
        2 => ("RAW".to_string(), env::args().nth(1).unwrap()),
        3 => (env::args().nth(1).unwrap(), env::args().nth(2).unwrap()),
        _ => {
            println!("Usage:    {} [type] 'program'", env::args().nth(0).unwrap());
            println!("  type: a pcap linklayer type, e.g:");
            println!("      RAW, EN10MB");
            println!("  program: a pcap filter expression e.g.:");
            println!("      'tcp port 80'");
            println!("      'host 10.0.0.5'");
            println!("      'icmp and greater 1000'");
            process::exit(1);
        }
    };

    let lt = match Linktype::from_name(&layertype) {
        Ok(t) => t,
        Err(_) => {
            println!("Invalid linklayer type {}", layertype);
            process::exit(1);
        },
    };

    let mut h = Capture::dead(lt).unwrap();

    let p: Vec<pcap::bpf_insn> = match h.compile_filter(&prog) {
        Ok(p) => p,
        Err(e) => {
            println!("{:?}", e);
            process::exit(1);
        }
    };
    let def: String = p.iter()
        .map(|&op| format!("{} {} {} {}", op.code, op.jt, op.jf, op.k))
        .collect::<Vec<_>>()
        .join(",");
    println!("{},{}",p.len(), def);
}
