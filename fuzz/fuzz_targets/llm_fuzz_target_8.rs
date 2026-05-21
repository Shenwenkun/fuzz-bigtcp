#![no_main]
use libfuzzer_sys::fuzz_target;

use std::sync::Arc;

use aster_bigtcp::iface::{
    BindPortConfig, Iface, InterfaceFlags, InterfaceType, IpIface,
};
use aster_bigtcp::socket::{RawTcpOption, TcpConnection, TcpListener};
use bigtcp_user::mock::{
    MockExt, MockObserver, MockScheduleNextPoll, MockWithDeviceWithRxIp,
};
use bigtcp_kernel_mock::mock::Jiffies;

use smoltcp::wire::{IpEndpoint, Ipv4Address, Ipv4Cidr};



fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    // Build mock iface
    let dev = MockWithDeviceWithRxIp::new();
    let iface: Arc<dyn Iface<MockExt>> = IpIface::<MockWithDeviceWithRxIp, MockExt>::new(
        dev,
        Ipv4Cidr::new(Ipv4Address::new(127, 0, 0, 1), 24),
        "api_fuzz_multi".into(),
        MockScheduleNextPoll,
        InterfaceType::LOOPBACK,
        InterfaceFlags::empty(),
    );

    let option = RawTcpOption {
        keep_alive: None,
        is_nagle_enabled: true,
    };

    let mut conns: Vec<TcpConnection<MockExt>> = Vec::new();
    let mut listeners: Vec<TcpListener<MockExt>> = Vec::new();

    let mut now = 0u64;

    for chunk in data.chunks(2) {
        if chunk.len() < 2 {
            break;
        }

        let op = chunk[0] % 16;
        let arg = chunk[1];

        match op {
            // 0: Connect (outgoing)
            0 => {
                let bound = match iface.bind(BindPortConfig::Ephemeral(true)) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let remote = IpEndpoint::new(
                    Ipv4Address::new(127, 0, 0, 2).into(),
                    10000 + (arg as u16),
                );
                let observer = MockObserver;
                if let Ok(c) = TcpConnection::new_connect(bound, remote, &option, observer) {
                    conns.push(c);
                }
            }

            // 1: CheckState
            1 => {
                if conns.is_empty() { continue; }
                let idx = (arg as usize) % conns.len();
                let c = &conns[idx];
                let _ = c.connect_state();
            }

            // 2: Send
            2 => {
                if conns.is_empty() { continue; }
                let idx = (arg as usize) % conns.len();
                let c = &conns[idx];

                let len = (arg as usize % 64) + 1;
                let buf = vec![0x41u8; len];
                let _ = c.send(|w| -> Result<usize, ((), usize)> {
                    let n = w.len().min(buf.len());
                    w[..n].copy_from_slice(&buf[..n]);
                    Ok(n)
                });
            }

            // 3: Recv
            3 => {
                if conns.is_empty() { continue; }
                let idx = (arg as usize) % conns.len();
                let c = &conns[idx];

                let buf = [0u8; 128];
                let _ = c.recv(|r| -> Result<usize, ((), usize)> {
                    let n = r.len().min(buf.len());
                    Ok(n)
                });
            }

            // 4: ShutSend
            4 => {
                if conns.is_empty() { continue; }
                let idx = (arg as usize) % conns.len();
                let c = &conns[idx];
                let _ = c.shut_send();
            }

            // 5: ShutRecv
            5 => {
                if conns.is_empty() { continue; }
                let idx = (arg as usize) % conns.len();
                let c = &conns[idx];
                let _ = c.shut_recv();
            }

            // 6: Close
            6 => {
                if conns.is_empty() { continue; }
                let idx = (arg as usize) % conns.len();
                let c = &conns[idx];
                c.close();
            }

            // 7: Reset
            7 => {
                if conns.is_empty() { continue; }
                let idx = (arg as usize) % conns.len();
                let c = &conns[idx];
                c.reset();
            }

            // 8: ClearRst
            8 => {
                if conns.is_empty() { continue; }
                let idx = (arg as usize) % conns.len();
                let c = &conns[idx];
                let _ = c.clear_rst_closed();
            }

            // 9: Tick
            9 => {
                now = now.wrapping_add((arg as u64 % 2000) + 1);
                Jiffies::set(now);
                iface.poll();
            }

            // 10: NewListener
            10 => {
                let port = 20000 + (arg as u16);

                let bound = match iface.bind(BindPortConfig::Specified(port)) {
                    Ok(b) => b,
                    Err(_) => continue,
                };

                let observer = MockObserver;

                let listener = match TcpListener::<MockExt>::new_listen(
                    bound,
                    16,
                    &option,
                    observer,
                ) {
                    Ok(l) => l,
                    Err(_) => continue,
                };

                listeners.push(listener);
            }

            // 11: Accept
            11 => {
                if listeners.is_empty() { continue; }
                let idx = (arg as usize) % listeners.len();
                let lst = &listeners[idx];
                let _ = lst.accept();
            }

            // 12: DropConn
            12 => {
                if conns.is_empty() { continue; }
                let idx = (arg as usize) % conns.len();
                let c = conns.remove(idx);
                c.close();
                iface.poll();
            }

            // 13: NewConn
            13 => {
                let bound = match iface.bind(BindPortConfig::Ephemeral(true)) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let remote = IpEndpoint::new(
                    Ipv4Address::new(127, 0, 0, 3).into(),
                    30000 + (arg as u16),
                );
                let observer = MockObserver;
                if let Ok(c) = TcpConnection::new_connect(bound, remote, &option, observer) {
                    conns.push(c);
                }
            }

            // 14: Rebind
            14 => {
                let _ = iface.bind(BindPortConfig::Ephemeral(arg % 2 == 0));
            }

            // 15: MultiTick
            15 => {
                let count = (arg % 10) + 1;
                for _ in 0..count {
                    now = now.wrapping_add(500);
                    Jiffies::set(now);
                    iface.poll();
                }
            }

            _ => {}
        }
    }

    // Cleanup connections
    for c in &conns {
        c.close();
    }
    iface.poll();

    // Cleanup listeners
    for lst in &listeners {
        lst.close();
    }
    iface.poll();
});
