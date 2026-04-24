#![no_main]
use libfuzzer_sys::fuzz_target;

use smoltcp::wire::{Ipv4Address, Ipv4Cidr};
use aster_bigtcp::iface::{IpIface, InterfaceFlags, InterfaceType};
use bigtcp_user::mock::{MockWithDeviceWithRxIp, MockExt, MockScheduleNextPoll};
use aster_bigtcp::iface::Iface;
use bigtcp_kernel_mock::mock::Jiffies;
use std::sync::Arc;

fn parse_framed_packets(data: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    let mut i = 0;

    while i + 2 <= data.len() {
        let ptype = data[i];
        let len = data[i + 1] as usize;
        i += 2;

        if i + len > data.len() {
            break;
        }

        out.push((ptype, &data[i..i + len]));
        i += len;
    }

    out
}

fuzz_target!(|data: &[u8]| {
    let dev = MockWithDeviceWithRxIp::new();
    let dev_handle = dev.dev.clone();

    let mut conns = Vec::new();
    let mut i = 0;

    while i < data.len() && conns.len() < 3 {
        let len = (data[i] as usize % 40) + 5;
        let end = (i + len).min(data.len());
        conns.push(parse_framed_packets(&data[i..end]));
        i = end;
    }

    {
        let mut inner = dev.dev.lock().unwrap();
        for conn in &conns {
            for (_ptype, payload) in conn {
                inner.inject(payload);
            }
        }
    }

    let flags = InterfaceFlags::from_bits_truncate(data.get(0).copied().unwrap_or(0) as u32);

    let iface_type = if data.get(1).copied().unwrap_or(0) & 1 == 0 {
        InterfaceType::LOOPBACK
    } else {
        InterfaceType::NETROM
    };


    let iface: Arc<dyn Iface<MockExt>> =
        IpIface::<MockWithDeviceWithRxIp, MockExt>::new(
            dev,
            Ipv4Cidr::new(Ipv4Address::new(127, 0, 0, 1), 24),
            "fuzz3".into(),
            MockScheduleNextPoll,
            iface_type,
            flags,
        );


    let mut now = 0u64;

    for _ in 0..200 {
        iface.poll();

        if now % 7 == 0 {
            now += 2000;
        } else {
            now += 10;
        }
        Jiffies::set(now);

        if now > 1_000_000 {
            break;
        }

        {
            let mut guard = dev_handle.lock().unwrap();
            let _ = guard.take_tx_packets();
        }
    }


    iface.poll();
});
