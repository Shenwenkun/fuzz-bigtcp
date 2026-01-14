#![no_main]
use libfuzzer_sys::fuzz_target;

use smoltcp::wire::{Ipv4Address, Ipv4Cidr};
use aster_bigtcp::iface::{IpIface, InterfaceFlags, InterfaceType};
use bigtcp_user::mock::{MockWithDeviceWithRx, MockExt, MockScheduleNextPoll};
use aster_bigtcp::iface::Iface;

fuzz_target!(|data: &[u8]| {
    // 1. 构造 mock 设备
    let dev = MockWithDeviceWithRx::new();

    // 2. 注入 fuzz 输入
    dev.dev.lock().unwrap().inject(data);

    // 3. 构造 iface
    let iface = IpIface::<MockWithDeviceWithRx, MockExt>::new(
        dev,
        Ipv4Cidr::new(Ipv4Address::new(127, 0, 0, 1), 24),
        "fuzz".into(),
        MockScheduleNextPoll,
        InterfaceType::LOOPBACK,
        InterfaceFlags::empty(),
    );

    // 4. 只 poll 一次，不要提前 return，不要 unwrap，不要 loop
    for _ in 0..10 {
        let _ = iface.poll();
    }

});
