#![no_main]
use libfuzzer_sys::fuzz_target;

use smoltcp::wire::{Ipv4Address, Ipv4Cidr};
use aster_bigtcp::iface::{IpIface, InterfaceFlags, InterfaceType};
use bigtcp_user::mock::{MockWithDeviceWithRxIp, MockExt, MockScheduleNextPoll};
use aster_bigtcp::iface::Iface;

fuzz_target!(|data: &[u8]| {
    // 1. 构造 mock 设备（还没 move 进 IpIface）
    let dev = MockWithDeviceWithRxIp::new();

    // 2. 在构造 iface 之前，把 fuzz 输入拆成多包并全部注入
    {
        let mut i = 0;
        let mut inner = dev.dev.lock().unwrap();

        while i < data.len() {
            let len = data[i] as usize;
            i += 1;

            if len == 0 {
                continue;
            }
            if i + len > data.len() {
                break;
            }

            let pkt = &data[i..i + len];
            i += len;

            inner.inject(pkt);
        }
    }

    // 3. 构造 iface（dev 在这里被 move 进去）
    let iface = IpIface::<MockWithDeviceWithRxIp, MockExt>::new(
        dev,
        Ipv4Cidr::new(Ipv4Address::new(127, 0, 0, 1), 24),
        "fuzz3".into(),
        MockScheduleNextPoll,
        InterfaceType::LOOPBACK,
        InterfaceFlags::empty(),
    );

    // 4. 多次 poll，模拟事件循环 / 时间推进
    for _ in 0..20 {
        let _ = iface.poll();
    }
});
