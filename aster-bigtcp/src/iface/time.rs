// SPDX-License-Identifier: MPL-2.0

#[cfg(feature = "user")]
use bigtcp_user::mock::Jiffies;


pub(super) fn get_network_timestamp() -> smoltcp::time::Instant {
    let millis = Jiffies::elapsed().as_millis();
    smoltcp::time::Instant::from_millis(millis as i64)
}
