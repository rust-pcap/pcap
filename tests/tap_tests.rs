/***
* These tests need to be run as root and currently only work on Linux (and maybe macOS?)
*
* To build and run these tests, run:
*

 cargo test --no-run --test tap_tests |& \
           sed -e 's/[()]//g' | \
           awk '/Executable/ {print $3" --include-ignored"}' | \
           xargs sudo

* which does the build as a non-priv user, extracts the exec binary location of
* the test from 'cargo test', and runs only that as root.
*
* To develop on these tests, you need to turn this feature on by hand in VS Code:
*
*  In VS Code, open the Extensions sidebar, click the gear icon next
*  to the rust-analyzer extension, and choose “Extension Settings.”
*  You can choose whether to customize settings for all projects (the
*  “User” tab) or just the current one (the “Workspace” tab). The
*  setting is labeled “Cargo: Features.”
*
* [from https://users.rust-lang.org/t/passing-feature-flags-to-rust-analyzer/45918/3]
*
* to debug, run:
*
* sudo rust-gdb ./target/debug/deps/tap_tests-${BUILD}
*  break tap_tests::tests::<TAB>   # to get a list of useful breakpoints
*
* NOTE: tests in Rust capture stdout and stderr by default; add "-- --nocapture", e.g.,
*  'cargo test -- --nocapture'
*/
#[cfg(not(windows))]
mod tests {

    use etherparse::{PacketBuilder, PacketHeaders};
    use pcap::Capture;
    use tun_rs::SyncDevice;

    /***
     * Create a Tap interface and make sure that the sendpacket() and next_packet()
     * work as expected
     */
    #[test]
    #[ignore]
    fn conntrack_tap_basic() {
        let (cap, iface) = capture_tap_interface();

        // NOTE: on Linux, if you don't specify a timeout(), it will never return
        let mut cap = cap.snaplen(32000).timeout(500).open().unwrap();

        // create a test packet
        let builder1 = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
            .ipv4([1, 2, 3, 4], [5, 6, 7, 8], 128)
            .tcp(80, 12345, 1, 32000);
        let payload1 = [1, 2, 3, 4, 5, 6, 7, 8];
        let mut pkt1 = Vec::with_capacity(builder1.size(payload1.len()));
        builder1.write(&mut pkt1, &payload1).unwrap();

        // send it into the interface
        let send_len = iface.send(&pkt1).unwrap();
        assert_eq!(send_len, pkt1.len());

        // try to pcap capture it
        let test_pkt1 = cap.next_packet().unwrap();
        // was the whole packet captured?
        assert_eq!(pkt1.len(), test_pkt1.header.caplen as usize);
        // does it match the packet that went in?
        assert_eq!(&pkt1, test_pkt1.data);

        // now, try to pcap send it back out that interface
        cap.sendpacket(pkt1.clone()).unwrap();

        let mut buf = vec![0; pkt1.len() * 2];
        let recv_len = iface.recv(&mut buf).unwrap();

        let (test_sendpkt, _) = buf.split_at(recv_len);
        if recv_len != pkt1.len() {
            // something else came back, so decode it and say what it was
            let weird = PacketHeaders::from_ethernet_slice(test_sendpkt).unwrap();
            panic!("weird packet !! {weird:#?}");
        }
        assert_eq!(pkt1.len(), recv_len);
        assert_eq!(pkt1, test_sendpkt);
    }

    /**
     * Bind a tap interface and attach a pcap capture to it and return both
     *
     * Return as a Capture<Inactive> in case the caller wants to set some
     * different options before opening it
     */
    fn capture_tap_interface() -> (Capture<pcap::Inactive>, SyncDevice) {
        use tun_rs::{DeviceBuilder, Layer};

        // Layer::L2 is a tap rather than a tun. The builder leaves IFF_NO_PI set unless
        // packet_information() asks for it, as described in
        // https://www.gabriel.urdhr.fr/2021/05/08/tuntap/#packet-information
        // it is not useful for l2 tap packets and would only complicate them
        let iface_result = DeviceBuilder::new()
            .name("testtap%d")
            .layer(Layer::L2)
            .build_sync();
        if let Err(e) = iface_result {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                println!("Permission denied - needs to be run as root/sudo!");
                panic!(
                    "Failed to bind the tap interface: PermissionDenied - please run with root/sudo!"
                );
            }
            // common error is to not run these tests as root; provide a nicer message
            panic!("Failed to bind the tap interface: {e:#?}");
        }
        let iface = iface_result.unwrap();
        let iface_name = iface.name().unwrap();
        if cfg!(target_os = "linux") {
            // If IPv6 is enabled, it will broadcast all sorts of stuff on this interface
            // these broadcasts will periodically (heisenbug!) break tests that aren't smart
            // enough to ignore them, so disable IPv6 on the test interface before any capture
            // starts. It has to happen BEFORE the interface comes up, else there is still a
            // race condition, and it was lost more often than not
            safe_run_command(format!(
                "sysctl -w net.ipv6.conf.{iface_name}.disable_ipv6=1"
            ));

            // Under Linux, the interface is created in the 'down' state, and pcap needs it 'up'
            // Shelling out instead of calling an API is a hack, but the netdev APIs are messy
            // TODO: consider moving to the https://crates.io/keywords/netlink crate
            safe_run_command(format!("ip link set dev {iface_name} up"));
        }
        let device = pcap::Device::from(iface_name.as_str());
        (Capture::from_device(device).unwrap(), iface)
    }

    /**
     * Run a command, check that it succeeded, and pretty print a panic message with its
     * stderr if it did not
     */
    fn safe_run_command(cmd: String) {
        use std::process::Command;

        let mut split_cmd = cmd.split_ascii_whitespace();
        // the first token is the program and the rest are args()
        let output = Command::new(split_cmd.next().unwrap())
            .args(split_cmd.collect::<Vec<&str>>())
            .output()
            .unwrap();
        if !output.status.success() {
            panic!(
                "safe_run_command FAILED: '{}' command returned stderr '{:#?}'",
                cmd,
                String::from_utf8(output.stderr)
            );
        }
    }
}
