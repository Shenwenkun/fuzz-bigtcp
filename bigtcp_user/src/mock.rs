use std::sync::Mutex;

// smoltcp 设备接口
use smoltcp::phy::{
    Device, DeviceCapabilities, Medium, RxToken,
};

// smoltcp 时间
use smoltcp::time::Instant;

// bigtcp 的 trait
use aster_bigtcp::device::{WithDevice,NotifyDevice};


pub struct MockDevice;

impl Device for MockDevice {
    type RxToken<'a> = MockRxToken;
    type TxToken<'a> = MockTxTokenEmpty;

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
        Some(MockTxTokenEmpty)
    }

}

pub struct MockTxTokenEmpty;

impl smoltcp::phy::TxToken for MockTxTokenEmpty {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        f(&mut buf[..])
    }
}


//
// 7. MockDeviceWithRxIp —— 支持 fuzz 输入作为收到的网络包
//
pub struct MockDeviceWithRxIp {
    pub packet: Option<Vec<u8>>,
    pub tx_packets: Vec<Vec<u8>>,   // ★ 新增：保存 TX 包
}

impl MockDeviceWithRxIp {
    pub fn new() -> Self {
        Self { 
            packet: None,
            tx_packets: Vec::new(),
        }
    }

    pub fn inject(&mut self, data: &[u8]) {
        self.packet = Some(data.to_vec());
    }

    pub fn take_tx_packets(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.tx_packets)
    }
}


impl Device for MockDeviceWithRxIp {
    type RxToken<'a> = MockRxTokenWithData;
    type TxToken<'a> = MockTxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1500;
        caps.medium = Medium::Ip;
        caps
    }

    fn receive(&mut self, _ts: Instant)
        -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)>
    {
        if let Some(data) = self.packet.take() {
            Some((
                MockRxTokenWithData(data),
                MockTxToken { tx: &mut self.tx_packets },
            ))
        } else {
            None
        }
    }

    fn transmit(&mut self, _ts: Instant)
        -> Option<Self::TxToken<'_>>
    {
        Some(MockTxToken { tx: &mut self.tx_packets })
    }
}



pub struct MockDeviceWithRxEth {
    pub packet: Option<Vec<u8>>,
    pub tx_packets: Vec<Vec<u8>>,
}

impl MockDeviceWithRxEth {
    pub fn new() -> Self {
        Self { packet: None, tx_packets: Vec::new() }
    }
    pub fn inject(&mut self, data: &[u8]) { self.packet = Some(data.to_vec()); }
    pub fn take_tx_packets(&mut self) -> Vec<Vec<u8>> { std::mem::take(&mut self.tx_packets) }
}

impl Device for MockDeviceWithRxEth {
    type RxToken<'a> = MockRxTokenWithData;
    type TxToken<'a> = MockTxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1500;
        caps.medium = Medium::Ethernet;   // 给 EtherIface 用
        caps
    }

    fn receive(&mut self, _ts: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(data) = self.packet.take() {
            Some((MockRxTokenWithData(data), MockTxToken { tx: &mut self.tx_packets }))
        } else { None }
    }

    fn transmit(&mut self, _ts: Instant) -> Option<Self::TxToken<'_>> {
        Some(MockTxToken { tx: &mut self.tx_packets })
    }
}

impl NotifyDevice for MockDeviceWithRxEth {
    fn notify_poll_end(&mut self) { /* no-op */ }
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
pub struct MockTxToken<'a> {
    pub tx: &'a mut Vec<Vec<u8>>,
}

impl smoltcp::phy::RxToken for MockRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(& [u8]) -> R,
    {
        f(&[])
    }
}

impl<'a> smoltcp::phy::TxToken for MockTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let result = f(&mut buf[..]);

        // ★ 保存 TX 包
        self.tx.push(buf);

        result
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
// 8. MockWithDeviceWithRxIp —— 让 fuzz 输入真正进入协议栈
//
use std::sync::Arc;

pub struct MockWithDeviceWithRxIp {
    pub dev: Arc<Mutex<MockDeviceWithRxIp>>,
}

impl MockWithDeviceWithRxIp {
    pub fn new() -> Self {
        Self {
            dev: Arc::new(Mutex::new(MockDeviceWithRxIp::new())),
        }
    }
}


impl WithDevice for MockWithDeviceWithRxIp {
    type Device = MockDeviceWithRxIp;

    fn with<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut Self::Device) -> R,
    {
        let mut guard = self.dev.lock().unwrap();
        f(&mut *guard)
    }
}


pub struct MockWithDeviceWithRxEth { 
    pub dev: Arc<Mutex<MockDeviceWithRxEth>>
}

impl MockWithDeviceWithRxEth {
    pub fn new() -> Self { Self { dev: Arc::new(Mutex::new(MockDeviceWithRxEth::new())) } }
}
impl WithDevice for MockWithDeviceWithRxEth {
    type Device = MockDeviceWithRxEth;
    fn with<F, R>(&self, f: F) -> R where F: FnOnce(&mut Self::Device) -> R {
        let mut guard = self.dev.lock().unwrap();
        f(&mut *guard)
    }
}

