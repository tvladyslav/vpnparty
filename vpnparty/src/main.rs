mod broadcast_listener;
mod cli_parser;
mod logger;
mod multicast_discovery;
mod network_devices;
mod udp_discovery;
mod udp;

use pcap::{Active, Capture, Device};
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::mpsc;
use std::thread;
use std::vec::Vec;

const MULTICAST_IP: &str = "239.1.2.3";
const MULTICAST_PORT: u16 = 54929;
const UDPING_PORT: u16    = 54928;

const SUP_LEN: usize = 6;
const SUP: [u8; SUP_LEN] = [0x00, 0x01, 0x53, 0x75, 0x70, 0x21];
const SUP_REPLY: [u8; 10] = [0x01, 0x53, 0x75, 0x70, 0x2c, 0x20, 0x62, 0x72, 0x6f, 0x21];

// TODO:
//   --version (app and Sup protocol)

/// VPN device and related destination IPs
struct Direction {
    vpnip: Ipv4Addr,
    // vpndevice: Device,
    vpncap: Capture<Active>,
    buddyip: HashSet<Ipv4Addr>,
}

enum Vpacket {
    /// Broadcast packet body
    B(Vec<u8>),

    /// IP address gathered via multicast
    M((usize, Ipv4Addr)),

    /// IP address gathered via udping
    U((usize, Ipv4Addr)),
}

/// Macro to cast any error type to String
/// //TODO: verify
#[macro_export]
macro_rules! e {
    ($($arg:tt)+) => ($($arg)+.map_err(|e| e.to_string())?)
}

fn main() -> Result<(), String> {
    let args: cli_parser::Arguments = cli_parser::parse_args()?;
    debug!("{:?}", args);

    let devices: network_devices::ParsedDevices = network_devices::get_devices(&args)?;
    debug!("{:?}", devices);

    let srcdev: Device = devices.src.clone();
    let mut vpn_ipv4_cap: Vec<Direction> = network_devices::open_dst_devices(devices, &args.buddyip)?;

    let (tx, rx) = mpsc::channel();

    // Init multicast peer discovery
    if !args.no_multicast {
        // Get multicast IP address and port
        let multicast_ip = args.mip.unwrap_or(e!(Ipv4Addr::from_str(MULTICAST_IP)));
        let multicast_port = args.mport.unwrap_or(MULTICAST_PORT);

        // Listen VPN devices for multicast discovery packets
        for (direction_id, d) in vpn_ipv4_cap.iter().enumerate() {
            let mtx = tx.clone();
            let vpnip = d.vpnip;
            let _multicast_handle = thread::spawn(move || {
                let _ = multicast_discovery::run_multicast(direction_id, mtx, vpnip, multicast_ip, multicast_port);
            });
        }

        info!("Multicast peer discovery initialized.");
    }

    // Init udping peer discovery
    if !args.no_udping {
        let udping_port = args.uport.unwrap_or(UDPING_PORT);

        for (direction_id, d) in vpn_ipv4_cap.iter().enumerate() {
            let utx = tx.clone();
            let vpnip = d.vpnip;
            let _udping_handle = thread::spawn(move || {
                let _ = udp_discovery::run_udping(direction_id, utx, vpnip, udping_port);
            });
        }

        info!("UDP peer discovery initialized.");
    }

    // Capture game-related broadcast packets
    {
        let btx = tx.clone();
        let _broadcast_handle = thread::spawn(move || {
            let _ = broadcast_listener::listen_broadcast(srcdev, btx, &args.port);
        });

        info!("Broadcast listener initialized.");
    }

    // No panics, unwraps or "?" in this loop. Report failures and proceed to next packet.
    loop {
        let packet: Vpacket = match rx.recv() {
            Ok(p) => p,
            Err(e) => {
                error!("Can't receive a packet: {}", e);
                continue;
            }
        };

        match packet {
            Vpacket::B(data) => {
                // Start from 14th byte to skip Ethernet Frame.
                // let no_eth_packet_len = data.len() - 14;
                for d in &mut vpn_ipv4_cap {
                    for dstip in &d.buddyip {
                        // TODO: send via LAN as well!
                        let no_ether_pktbuf: Vec<u8> = udp::craft_udp_packet(
                            &data[14..],
                            &d.vpnip.octets(),
                            &dstip.octets(),
                            None,
                        );

                        trace!("B {:?}", no_ether_pktbuf);

                        if let Err(e) = d.vpncap.sendpacket(&*no_ether_pktbuf) {
                            error!("Error while resending packet: {}", e);
                        }
                    }
                }
            }
            Vpacket::M((direction_id, sup_ip)) => {
                let is_new = vpn_ipv4_cap[direction_id].buddyip.insert(sup_ip);
                if is_new {
                    info!("{} joined the party!", sup_ip);
                }
                trace!("M {}", sup_ip);
            }
            Vpacket::U((direction_id, sup_ip)) => {
                let is_new = vpn_ipv4_cap[direction_id].buddyip.insert(sup_ip);
                if is_new {
                    info!("{} joined the party!", sup_ip);
                }
                trace!("U {}", sup_ip);
            }
        }
    }
    // e!(broadcast_handle.join());
}
