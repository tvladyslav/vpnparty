use std::sync::mpsc::Sender;

use pcap::{Device, Packet};

use crate::{e, error};

pub struct Bpacket {
    pub len: usize,
    pub data: Vec<u8>,
}

pub fn listen_broadcast(srcdev: Device, btx: Sender<Bpacket>) -> Result<(), String> {
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
                error!("Error while receiving packet: {}", e);
                continue;
            }
        };

        if packet.header.len <= 42 {
            error!("This packet is empty, skipping.");
            continue;
        }

        let r: Bpacket = Bpacket {len: packet.header.len as usize, data: packet.data.to_vec() };

        e!(btx.send(r));
    }
}
