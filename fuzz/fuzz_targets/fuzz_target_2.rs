#![no_main]
use libfuzzer_sys::fuzz_target;

use smoltcp::wire::{Ipv4Address, Ipv4Cidr};
use aster_bigtcp::iface::{IpIface, InterfaceFlags, InterfaceType};
use bigtcp_user::mock::{MockWithDeviceWithRxIp, MockExt, MockScheduleNextPoll};
use aster_bigtcp::iface::Iface;

fuzz_target!(|data: &[u8]| {

    let dev = MockWithDeviceWithRxIp::new();

    dev.dev.lock().unwrap().inject(data);

    let iface = IpIface::<MockWithDeviceWithRxIp, MockExt>::new(
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
