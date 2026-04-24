#![no_main]

use libfuzzer_sys::fuzz_target;

use aster_bigtcp::errors::tcp as btcp;
use aster_bigtcp::errors::udp as budp;
use aster_bigtcp::errors::*;

use smoltcp::socket::tcp as stcp;
use smoltcp::socket::udp as sudp;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    match data[0] % 6 {
        // Tcp::ListenError::from
        0 => {
            let _ = btcp::ListenError::from(stcp::ListenError::InvalidState);
            let _ = btcp::ListenError::from(stcp::ListenError::Unaddressable);
            match btcp::ListenError::AddressInUse {
                btcp::ListenError::AddressInUse => {}
                _ => {}
            }
        }

        // Tcp::ConnectError::from
        1 => {
            let _ = btcp::ConnectError::from(stcp::ConnectError::InvalidState);
            let _ = btcp::ConnectError::from(stcp::ConnectError::Unaddressable);
            match btcp::ConnectError::AddressInUse {
                btcp::ConnectError::AddressInUse => {}
                _ => {}
            }
        }

        // Tcp::SendError::from
        2 => {
            let _ = btcp::SendError::from(stcp::SendError::InvalidState);
            match btcp::SendError::ConnReset {
                btcp::SendError::ConnReset => {}
                _ => {}
            }
        }

        // Tcp::RecvError::from
        3 => {
            let _ = btcp::RecvError::from(stcp::RecvError::InvalidState);
            let _ = btcp::RecvError::from(stcp::RecvError::Finished);
            match btcp::RecvError::ConnReset {
                btcp::RecvError::ConnReset => {}
                _ => {}
            }
        }

        // Udp::SendError::from
        4 => {
            let _ = budp::SendError::from(sudp::SendError::Unaddressable);
            let _ = budp::SendError::from(sudp::SendError::BufferFull);
            match budp::SendError::TooLarge {
                budp::SendError::TooLarge => {}
                _ => {}
            }
        }

        5 => {
            match budp::RecvError::Exhausted {
                budp::RecvError::Exhausted => {}
                _ => {}
            }
            match budp::RecvError::Truncated {
                budp::RecvError::Truncated => {}
                _ => {}
            }
        }
        6 => {
            let _ = BindError::Exhausted;
            let _ = BindError::InUse;
        }

        _ => {}
    }
});
