use std::sync::mpsc::Sender;

use pcap::{Device, Packet};

use crate::{debug, e, error, Vpacket};

pub fn listen_broadcast(srcdev: Device, btx: Sender<Vpacket>, ports: &[u16]) -> Result<(), String> {
    let port_filter: String = if !ports.is_empty() {
        let placeholder: String = format!(" and ((dst port {})", ports[0]);
        let mut pstr = ports.iter().skip(1).fold(placeholder, |acc, p: &u16| {
            acc + &format!(" or (dst port {})", p)
        });
        pstr.push(')');
        pstr
    } else {
        String::new()
    };

    let full_filter = format!(
        "(ip broadcast) and (src host {}){}",
        srcdev.addresses[0].addr, port_filter
    );
    debug!("Broadcast filter: {}", full_filter);

    // Setup Capture
    let mut hw_cap = e!(e!(pcap::Capture::from_device(srcdev))
        .immediate_mode(false)
        .timeout(569) // This is a workaround, because immediate mode doesn't work in Win11 build
        .open());

    e!(hw_cap.filter(full_filter.as_str(), true));

    // TODO: make a breaking condition
    loop {
        let p = hw_cap.next_packet();
        let packet: Packet = match p {
            Ok(p) => p,
            Err(e) => {
                let pcap::Error::TimeoutExpired = e else {
                    error!("Error while receiving broadcast packet: {}", e);
                    continue;
                };
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
