#![no_main]
use libfuzzer_sys::fuzz_target;
use smoltcp::wire::Ipv4Packet;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::ipv4::Repr;

fuzz_target!(|data: &[u8]| {
    let mut buf = [0u8; 20];
    let packet = if data.len() < 20 {
        buf[..data.len()].copy_from_slice(data);
        &buf
    } else {
        data
    };

    if let Ok(pkt) = Ipv4Packet::new_checked(packet) {
        let _ = pkt.version();
        let _ = pkt.header_len();
        let _ = pkt.dscp();
        let _ = pkt.ecn();
        let _ = pkt.total_len();
        let _ = pkt.ident();
        let _ = pkt.dont_frag();
        let _ = pkt.more_frags();
        let _ = pkt.frag_offset();
        let _ = pkt.hop_limit();
        let _ = pkt.next_header();
        let _ = pkt.checksum();
        let _ = pkt.src_addr();
        let _ = pkt.dst_addr();
        let _ = pkt.verify_checksum();
        let _ = pkt.payload();


        let caps = ChecksumCapabilities::default();
        let _ = Repr::parse(&pkt, &caps);


        if let Ok(repr) = Repr::parse(&pkt, &caps) {
            let mut out = vec![0u8; repr.buffer_len() + repr.payload_len];
            let mut out_pkt = Ipv4Packet::new_unchecked(&mut out);
            repr.emit(&mut out_pkt, &caps);
        }
    }
});
