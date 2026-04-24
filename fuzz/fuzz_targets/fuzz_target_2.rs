#![no_main]
use libfuzzer_sys::fuzz_target;

use smoltcp::wire::{Ipv4Address, Ipv4Cidr};
use aster_bigtcp::iface::{IpIface, InterfaceFlags, InterfaceType};
use bigtcp_user::mock::{MockWithDeviceWithRxIp, MockExt, MockScheduleNextPoll};
use aster_bigtcp::iface::Iface;
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    let dev = MockWithDeviceWithRxIp::new();


    {
        let mut i = 0;
        let mut inner = dev.dev.lock().unwrap();

        while i < data.len() {
            if i + 1 > data.len() {
                break;
            }

            let len = data[i] as usize;
            i += 1;

            if len == 0 || i + len > data.len() {
                break;
            }

            let pkt = &data[i..i + len];
            i += len;

            inner.inject(pkt);
        }
    }


    let flags = if data.len() > 0 {
        InterfaceFlags::from_bits_truncate(data[0] as u32)
    } else {
        InterfaceFlags::empty()
    };


    let iface_type = if data.len() > 1 && data[1] & 1 == 0 {
        InterfaceType::LOOPBACK
    } else {
        InterfaceType::NETROM
    };

    let iface: Arc<dyn Iface<MockExt>> = IpIface::<MockWithDeviceWithRxIp, MockExt>::new(
        dev,
        Ipv4Cidr::new(Ipv4Address::new(127, 0, 0, 1), 24),
        "fuzz2".into(),
        MockScheduleNextPoll,
        iface_type,
        flags,
    );

    let polls = if data.len() > 2 { (data[2] as usize % 50) + 10 } else { 10 };

    for _ in 0..polls {
        let _ = iface.poll();
    }
});
