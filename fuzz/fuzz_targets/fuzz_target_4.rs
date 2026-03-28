#![no_main]
use libfuzzer_sys::fuzz_target;

use smoltcp::wire::{Ipv4Address, Ipv4Cidr};

use aster_bigtcp::iface::{IpIface, InterfaceFlags, InterfaceType};
use bigtcp_user::mock::{MockWithDeviceWithRx, MockExt, MockScheduleNextPoll};
use bigtcp_kernel_mock::mock::Jiffies;
use aster_bigtcp::iface::Iface;
use std::sync::Arc;

// -------------------- TCP 构造器 --------------------
use smoltcp::wire::{TcpControl, Ipv4Repr, Ipv4Packet, TcpRepr, TcpPacket, IpProtocol, TcpSeqNumber};
use smoltcp::phy::ChecksumCapabilities;

// 从 payload 中解析 seq/ack + data：
// payload = [ seq(4) | ack(4) | data... ]
fn split_seq_ack_payload(payload: &[u8]) -> Option<(u32, u32, &[u8])> {
    if payload.len() < 8 {
        return None;
    }
    let seq = u32::from_le_bytes(payload[0..4].try_into().ok()?);
    let ack = u32::from_le_bytes(payload[4..8].try_into().ok()?);
    let data = &payload[8..];
    Some((seq, ack, data))
}

fn build_syn(payload: &[u8]) -> Vec<u8> {
    use smoltcp::wire::{
        Ipv4Repr, Ipv4Packet, TcpRepr, TcpPacket,
        IpProtocol, TcpControl, Ipv4Address, TcpSeqNumber,
    };
    use smoltcp::phy::ChecksumCapabilities;

    // ---- TCP header ----
    let tcp_repr = TcpRepr {
        src_port: 12345,
        dst_port: 80,
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(0),
        ack_number: None,
        window_len: 1024,

        // 你的版本新增字段（必须全部填）
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,

        payload,
    };

    // ---- IPv4 header ----
    let ip_repr = Ipv4Repr {
        src_addr: Ipv4Address::new(127, 0, 0, 2),   // 随便一个同网段地址
        dst_addr: Ipv4Address::new(127, 0, 0, 1),   // 必须等于 iface 绑定的地址
        next_header: IpProtocol::Tcp,
        payload_len: tcp_repr.buffer_len(),
        hop_limit: 64,
    };

    let ip_len = ip_repr.buffer_len();
    let tcp_len = tcp_repr.buffer_len();

    let mut buffer = vec![0u8; ip_len + tcp_len];

    // ---- emit IPv4 header ----
    {
        let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut buffer[..ip_len]);
        ip_repr.emit(&mut ipv4_packet, &ChecksumCapabilities::default());
    }

    // ---- emit TCP header ----
    {
        let mut tcp_packet = TcpPacket::new_unchecked(&mut buffer[ip_len..]);
        tcp_repr.emit(
            &mut tcp_packet,
            &ip_repr.src_addr.into(),
            &ip_repr.dst_addr.into(),
            &ChecksumCapabilities::default(),
        );
    }

    buffer
}

fn build_tcp_with_control(
    control: TcpControl,
    payload: &[u8],
    last_server_seq: Option<i32>,
) -> Vec<u8> {
    use smoltcp::wire::{
        Ipv4Repr, Ipv4Packet, TcpRepr, TcpPacket,
        IpProtocol, Ipv4Address, TcpSeqNumber,
    };
    use smoltcp::phy::ChecksumCapabilities;

    if payload.len() < 8 {
        return vec![];
    }

    let seq = u32::from_le_bytes(payload[0..4].try_into().unwrap());
    let ack = u32::from_le_bytes(payload[4..8].try_into().unwrap());
    let data = &payload[8..];

    let tcp_repr = TcpRepr {
        src_port: 12345,
        dst_port: 80,
        control,
        seq_number: TcpSeqNumber(seq as i32),
        ack_number: last_server_seq.map(|s| TcpSeqNumber(s + 1)),
        window_len: 1024,
        window_scale: None,
        max_seg_size: None,
        sack_permitted: false,
        sack_ranges: [None, None, None],
        timestamp: None,
        payload: data,
    };

    let ip_repr = Ipv4Repr {
        src_addr: Ipv4Address::new(127, 0, 0, 2),
        dst_addr: Ipv4Address::new(127, 0, 0, 1),
        next_header: IpProtocol::Tcp,
        payload_len: tcp_repr.buffer_len(),
        hop_limit: 64,
    };

    let ip_len = ip_repr.buffer_len();
    let tcp_len = tcp_repr.buffer_len();
    let mut buffer = vec![0u8; ip_len + tcp_len];

    {
        let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut buffer[..ip_len]);
        ip_repr.emit(&mut ipv4_packet, &ChecksumCapabilities::default());
    }
    {
        let mut tcp_packet = TcpPacket::new_unchecked(&mut buffer[ip_len..]);
        tcp_repr.emit(
            &mut tcp_packet,
            &ip_repr.src_addr.into(),
            &ip_repr.dst_addr.into(),
            &ChecksumCapabilities::default(),
        );
    }

    buffer
}


fn build_ack(payload: &[u8], last_server_seq: Option<i32>) -> Vec<u8> {
    build_tcp_with_control(TcpControl::None, payload, last_server_seq)
}


fn build_fin(payload: &[u8], last_server_seq: Option<i32>) -> Vec<u8> {
    build_tcp_with_control(TcpControl::Fin, payload, last_server_seq)
}

fn build_rst(payload: &[u8], last_server_seq: Option<i32>) -> Vec<u8> {
    build_tcp_with_control(TcpControl::Rst, payload, last_server_seq)
}

fn build_data(payload: &[u8], last_server_seq: Option<i32>) -> Vec<u8> {
    build_tcp_with_control(TcpControl::Psh, payload, last_server_seq)
}





fn build_tcp_packet(ptype: u8, payload: &[u8], last_server_seq: Option<i32>) -> Vec<u8> {
    match ptype {
        0x01 => build_syn(payload),
        0x02 => build_ack(payload, last_server_seq),
        0x03 => build_fin(payload, last_server_seq),
        0x04 => build_rst(payload, last_server_seq),
        0x05 => build_data(payload, last_server_seq),
        _    => build_syn(payload),
    }
}



// -------------------- 解析 IPv4+TCP，用于从 TX 包里提取 SYN+ACK --------------------
fn parse_ipv4_tcp(pkt: &[u8]) -> Option<(Ipv4Repr, TcpRepr)> {
    use smoltcp::wire::{Ipv4Packet, TcpPacket, IpProtocol};

    let ipv4 = Ipv4Packet::new_checked(pkt).ok()?;
    if ipv4.next_header() != IpProtocol::Tcp {
        return None;
    }

    let ip_repr = Ipv4Repr::parse(&ipv4, &ChecksumCapabilities::default()).ok()?;


    let tcp = TcpPacket::new_checked(ipv4.payload()).ok()?;
    let tcp_repr = TcpRepr::parse(
        &tcp,
        &ip_repr.src_addr.into(),
        &ip_repr.dst_addr.into(),
        &ChecksumCapabilities::default(),
    ).ok()?;

    Some((ip_repr, tcp_repr))
}



// -------------------- TLV framing --------------------
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

        let payload = &data[i..i + len];
        i += len;

        out.push((ptype, payload));
    }

    out
}

fuzz_target!(|data: &[u8]| {
    let dev = MockWithDeviceWithRx::new();
    let dev_handle = dev.dev.clone();   // Arc<Mutex<MockDeviceWithRx>>

    let packets = parse_framed_packets(data);
    let mut last_server_seq: Option<i32> = None;


    {
        let mut inner = dev.dev.lock().unwrap();
        for (ptype, payload) in packets {
            let pkt = build_tcp_packet(ptype, payload, last_server_seq);
            inner.inject(&pkt);
        }
    }

    let iface: Arc<dyn Iface<MockExt>> =
        IpIface::<MockWithDeviceWithRx, MockExt>::new(
            dev,
            Ipv4Cidr::new(Ipv4Address::new(127, 0, 0, 1), 24),
            "fuzz4".into(),
            MockScheduleNextPoll,
            InterfaceType::LOOPBACK,
            InterfaceFlags::empty(),
        );

    // 键：创建 TCP listener
    
    use aster_bigtcp::socket::TcpListener;
    use aster_bigtcp::iface::BindPortConfig;
    use aster_bigtcp::socket::RawTcpOption;
    use bigtcp_user::mock::MockObserver;

    let option = RawTcpOption {
        keep_alive: None,
        is_nagle_enabled: true,
    };

    let bound = match iface.bind(BindPortConfig::Specified(80)) {
        Ok(b) => b,
        Err(_) => return, // 这一轮算了
    };
    let observer = MockObserver;

    let listener = match TcpListener::<MockExt>::new_listen(bound, 16, &option, observer) {
        Ok(l) => l,
        Err((_bound, _err)) => return,
    };

    

    let mut now = 0u64;

    for _ in 0..200 {
        iface.poll();
        now += 10;
        Jiffies::set(now);

        // 从 TX 捕获 SYN+ACK，更新 last_server_seq
        {
            let mut guard = dev_handle.lock().unwrap();
            let txs = guard.take_tx_packets();
            drop(guard);

            for pkt in txs {
                if let Some((_ip, tcp)) = parse_ipv4_tcp(&pkt) {
                    if tcp.control == TcpControl::Syn && tcp.ack_number.is_some() {
                        last_server_seq = Some(tcp.seq_number.0);
                    }
                }
            }
        }


        if now > 1_000_000 {
            break;
        }
    }

    listener.close();

    iface.poll();

    drop(listener);
});
