// SPDX-FileCopyrightText: 2026 Vladyslav Tsilytskyi
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::mpsc::Sender;

use pcap::{Device, Packet};

use crate::pcap_filter::host_filter;
use crate::{debug, e, error, Vpacket};

pub fn listen_mdns(srcdev: Device, btx: Sender<Vpacket>) -> Result<(), String> {
    let host_filter: String = host_filter(&srcdev.addresses);
    let mdns_filter: String = format!(
        "ip and {} and (dst host 224.0.0.251) and (udp dst port 5353)",
        host_filter
    );
    debug!("mDNS filter: {}", mdns_filter);

    // Setup Capture
    let mut hw_cap = e!(e!(pcap::Capture::from_device(srcdev))
        .immediate_mode(false)
        .timeout(571) // This is a workaround, because immediate mode doesn't work in Win11 build
        .open());

    e!(hw_cap.filter(mdns_filter.as_str(), true));

    // TODO: make a breaking condition
    loop {
        let p = hw_cap.next_packet();
        let packet: Packet = match p {
            Ok(p) => p,
            Err(e) => {
                let pcap::Error::TimeoutExpired = e else {
                    error!("Error while receiving mDNS packet: {}", e);
                    continue;
                };
                continue;
            }
        };

        if packet.header.len <= 42 {
            error!("This packet is empty, skipping.");
            continue;
        }

        e!(btx.send(Vpacket::D(packet.data.to_vec())));
    }
}
