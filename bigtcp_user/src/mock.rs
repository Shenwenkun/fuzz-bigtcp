use std::sync::Mutex;

// smoltcp 设备接口
use smoltcp::phy::{
    Device, DeviceCapabilities, Medium, RxToken,
};

// smoltcp 时间
use smoltcp::time::Instant;

// bigtcp 的 trait
use aster_bigtcp::device::WithDevice;
use aster_bigtcp::ext::Ext;
use aster_bigtcp::socket::{SocketEventObserver, SocketEvents};



pub struct MockDevice;

impl Device for MockDevice {
    type RxToken<'a> = MockRxToken;
    type TxToken<'a> = MockTxToken;

    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.max_transmission_unit = 1500;
        caps.medium = smoltcp::phy::Medium::Ip;
        caps
    }

    fn receive(&mut self, _ts: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> { 
        None 
    }

    fn transmit(&mut self, _ts: Instant) -> Option<Self::TxToken<'_>> { 
        Some(MockTxToken) 
    }
}

//
// 7. MockDeviceWithRx —— 支持 fuzz 输入作为收到的网络包
//
pub struct MockDeviceWithRx {
    pub packet: Option<Vec<u8>>,
}

impl MockDeviceWithRx {
    pub fn new() -> Self {
        Self { packet: None }
    }

    pub fn inject(&mut self, data: &[u8]) {
        self.packet = Some(data.to_vec());
    }
}

impl Device for MockDeviceWithRx {
    type RxToken<'a> = MockRxTokenWithData;
    type TxToken<'a> = MockTxToken; // 复用之前的 TxToken

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1500;
        caps.medium = Medium::Ip;
        caps
    }

    fn receive(&mut self, _ts: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(data) = self.packet.take() {
            Some((MockRxTokenWithData(data), MockTxToken))
        } else {
            None
        }
    }

    fn transmit(&mut self,_ts: Instant) -> Option<Self::TxToken<'_>> {
        Some(MockTxToken)
    }
}

//
// RxToken：把 fuzz 输入交给协议栈
//
pub struct MockRxTokenWithData(Vec<u8>);

impl RxToken for MockRxTokenWithData {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(& [u8]) -> R,
    {
        let mut buf = self.0;
        f(&mut buf[..])
    }
}

pub struct MockRxToken;
pub struct MockTxToken;

impl smoltcp::phy::RxToken for MockRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(& [u8]) -> R,
    {
        f(&[])
    }
}

impl smoltcp::phy::TxToken for MockTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        // 分配一个 len 大小的 buffer 
        let mut buf = vec![0u8; len]; 
        f(&mut buf)
    }
}



pub struct MockWithDevice;

impl aster_bigtcp::device::WithDevice for MockWithDevice {
    type Device = MockDevice;

    fn with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Self::Device) -> R,
    {
        let mut dev = MockDevice;
        f(&mut dev)
    }
}


#[derive(Clone)]
pub struct MockObserver;

impl aster_bigtcp::socket::SocketEventObserver for MockObserver {
    fn on_events(&self, _event: aster_bigtcp::socket::SocketEvents) {}
}

pub struct MockScheduleNextPoll;

impl aster_bigtcp::iface::ScheduleNextPoll for MockScheduleNextPoll {
    fn schedule_next_poll(&self, _ms: Option<u64>) {
        // no-op
    }
}

pub struct MockExt;

impl aster_bigtcp::ext::Ext for MockExt {
    type ScheduleNextPoll = MockScheduleNextPoll;
    type TcpEventObserver = MockObserver;
    type UdpEventObserver = MockObserver;
}

//
// 8. MockWithDeviceWithRx —— 让 fuzz 输入真正进入协议栈
//
pub struct MockWithDeviceWithRx {
    pub dev: Mutex<MockDeviceWithRx>,
}

impl MockWithDeviceWithRx {
    pub fn new() -> Self {
        Self {
            dev: Mutex::new(MockDeviceWithRx::new()),
        }
    }
}

impl WithDevice for MockWithDeviceWithRx {
    type Device = MockDeviceWithRx;

    fn with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Self::Device) -> R,
    {
        let mut guard = self.dev.lock().unwrap();
        f(&mut *guard)
    }
}
