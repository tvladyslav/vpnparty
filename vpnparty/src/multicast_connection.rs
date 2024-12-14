use std::net::Ipv4Addr;
use std::sync::mpsc::Sender;

use pcap::{Device, Packet};

use crate::{e, error, trace, udp, Vpacket};

// TODO: randomize?
const IP_STARTING_ID: u16 = 0xb6cc;

// TODO: choose correct multicast IP, free port and TTL

#[rustfmt::skip]
const SUP_PACKET: [u8; 40] = [
    // IP header          Identific             TTL   UDP  checksum  SOURCE IP address       DESTINATION IP address
    0x45, 0x0, 0x0, 0x28, 0x00, 0x00, 0x0, 0x0, 0x1, 0x11, 0x0, 0x0, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x0, 0x0, 0x6d,
    // UDP header
    // src port dst port    length     checksum
    0xd6, 0x90, 0xd6, 0x90, 0x0, 0x14, 0x00, 0x00,
    // Payload: protocol version u32, Sup!, counter u32.
    0x00, 0x00, 0x00, 0x01, 0x53, 0x75, 0x70, 0x21, 0x00, 0x00, 0x00, 0x00
];

/// Peer discovery via multicast
pub fn run_multicast(
    direction_id: usize,
    mcdev: Device,
    btx: Sender<Vpacket>,
    src_ip: Ipv4Addr,
    multicast_ip: Ipv4Addr,
) -> Result<(), String> {
    let id: u16 = IP_STARTING_ID;
    let sup_hello = udp::craft_udp_packet(
        &SUP_PACKET,
        &src_ip.octets(),
        &multicast_ip.octets(),
        Some(id),
    );

    // Setup Capture
    let mut mc_cap = e!(e!(pcap::Capture::from_device(mcdev))
        .immediate_mode(true)
        .open());

    e!(mc_cap.filter(&format!("dst {} and udp", multicast_ip), true));

    // Send Sup! hello packet
    if let Err(e) = mc_cap.sendpacket(&*sup_hello) {
        error!("Can't send Sup! hello packet: {}", e);
    }

    // TODO: make a breaking condition
    loop {
        let p = mc_cap.next_packet();
        let packet: Packet = match p {
            Ok(p) => p,
            Err(e) => {
                error!("Error while receiving multicast packet: {}", e);
                continue;
            }
        };

        trace!("MMM {:?}", packet.data);    // TODO: remove

        // TODO: sup! reply with cooldown mechanism

        let ip: &[u8] = &packet.data[12..15];
        let sip: Ipv4Addr = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);

        if src_ip != sip {
            e!(btx.send(Vpacket::M((direction_id, sip))));
        }

    }
}
