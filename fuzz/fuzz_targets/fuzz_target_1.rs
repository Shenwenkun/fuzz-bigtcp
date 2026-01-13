#![no_main]
use libfuzzer_sys::fuzz_target;
use smoltcp::wire::Ipv4Packet;

fuzz_target!(|data: &[u8]| {
    let packet = if data.len() < 20 {
        [
            0x45, 0x00, 0x00, 0x14,
            0x00, 0x00, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0x7F, 0x00, 0x00, 0x01,
            0x7F, 0x00, 0x00, 0x01,
        ].as_ref()
    } else {
        data
    };

    let _ = Ipv4Packet::new_checked(packet);
});
