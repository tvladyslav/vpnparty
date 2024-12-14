use std::sync::mpsc::Sender;

use pcap::{Device, Packet};

use crate::{e, error, Vpacket};

pub fn listen_broadcast(srcdev: Device, btx: Sender<Vpacket>) -> Result<(), String> {
    // Setup Capture
    let mut hw_cap = e!(e!(pcap::Capture::from_device(srcdev))
        .immediate_mode(true)
        .open());

    e!(hw_cap.filter("dst 255.255.255.255 and udp", true));

    // TODO: make a breaking condition
    loop {
        let p = hw_cap.next_packet();
        let packet: Packet = match p {
            Ok(p) => p,
            Err(e) => {
                error!("Error while receiving broadcast packet: {}", e);
                continue;
            }
        };

        if packet.header.len <= 42 {
            error!("This packet is empty, skipping.");
            continue;
        }

        e!(btx.send(Vpacket::B(packet.data.to_vec())));
    }
}
