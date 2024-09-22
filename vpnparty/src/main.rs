use pcap::{Active, Capture, ConnectionStatus, Device};
use std::io::ErrorKind;
use std::net::IpAddr;
use std::vec::Vec;

// Not exhaustive, of course.
const VIRT_NAMES: [&str; 1] = ["Virtual"];
const VPN_NAMES: [&str; 2] = ["WireGuard", "OpenVPN"];
const HW_NAMES: [&str; 16] = [
    // Most popular first
    "Broadcom", "Intel(R)", "MediaTek", "Qualcomm", "Realtek",
    // And the rest in alphabet order
    "AC1200", "ASIX", "Atheros", "Chelsio", "D-Link", "Dell", "JMicron", "Marvell", "Mellanox",
    "QLogic", "Ralink",
];

//============ Configuration =====================
/// Resend the broadcast packet or modify it to regular UDP
const BROADCAST: bool = true;
//============ End config ========================

struct ParsedDevices<'v> {
    src: Option<&'v Device>,
    dst: Vec<&'v Device>,
    virt: Vec<&'v Device>,
}

/// Get list of all network adapters and filter out useless.
fn get_promising_devices() -> Result<Vec<Device>, pcap::Error> {
    let devs = pcap::Device::list()?;
    let filtered = devs
        .into_iter()
        .filter(|d| {
            d.flags.is_up()
                && !d.flags.is_loopback()
                && !d.addresses.is_empty()
                && d.flags.connection_status == ConnectionStatus::Connected
                && !d
                    .desc
                    .as_ref()
                    .unwrap_or(&String::new())
                    .contains("VirtualBox")
        })
        .collect();
    Ok(filtered)
}

/// Check whether any of the array elements appear in device description
fn contains<E>(d: &&Device, patterns: E) -> bool
where
    E: IntoIterator<Item = &'static str>,
{
    for e in patterns {
        if d.desc.clone().unwrap_or_default().contains(e) {
            return true;
        }
    }
    false
}

/// Decide which device provides broadcast packets and which needs them
fn split_to_src_and_dst(full_list: &[Device]) -> ParsedDevices {
    let dst: Vec<&Device> = full_list
        .iter()
        .filter(|d| contains(d, VPN_NAMES))
        .collect();
    let virt: Vec<&Device> = full_list
        .iter()
        .filter(|d| contains(d, VIRT_NAMES))
        .collect();
    let src: Option<&Device> = full_list.iter().find(|d| contains(d, HW_NAMES));
    if src.is_none() {
        let guess = full_list.iter().find(|d| !contains(d, VPN_NAMES));
        return ParsedDevices {
            src: guess,
            dst,
            virt,
        };
    }

    ParsedDevices { src, dst, virt }
}

fn verify_devices<'r>(pd: &'r ParsedDevices) -> Result<&'r Device, pcap::Error> {
    if !pd.virt.is_empty() {
        println!("WARNING!\n\tThere are active virtual network adapters in your system.");
        println!("\tTo prevent troubles either disable virtual adapters or specify the correct HW adapter via command line.");
        println!("\tHere are PowerShell commands (run as Administrator):");
        for vd in &pd.virt {
            println!(
                "\t\tDisable-NetAdapter -InterfaceDescription  \"{}\"",
                vd.desc.clone().unwrap()
            );
        }
        println!("\tFeel free to enable them back using following PowerShell commands:");
        for vd in &pd.virt {
            println!(
                "\t\tEnable-NetAdapter -InterfaceDescription  \"{}\"",
                vd.desc.clone().unwrap()
            );
        }
        // This is just a warning, continue execution and hope for best.
    }
    if pd.dst.is_empty() {
        println!("Can't find your VPN connection.");
        println!("Please specify it manually via CLI.");
        return Err(pcap::Error::IoError(ErrorKind::NotFound));
    }
    let src_dev = match pd.src {
        None => {
            println!("Can't find your HW network adapter.");
            println!("Please specify it manually via CLI.");
            return Err(pcap::Error::IoError(ErrorKind::NotFound));
        }
        Some(s) => s,
    };
    Ok(src_dev)
}

fn print_devices(devs: &[Device]) {
    println!("Devices:");
    for dev in devs {
        println!("{0}\t{1}", dev.name, dev.desc.clone().unwrap_or_default());
        for a in &dev.addresses {
            println!("\t{0}", a.addr);
        }
    }
}

fn main() -> Result<(), pcap::Error> {
    let devs: Vec<Device> = get_promising_devices()?;
    // TODO: CLI to disable prints
    print_devices(&devs);

    // TODO: CLI option to disable this heuristic
    let split_devices: ParsedDevices = split_to_src_and_dst(&devs);
    let src_dev: &Device = verify_devices(&split_devices)?;

    // Setup Capture
    // TODO: capture virtual devices as well?
    let mut hw_cap = pcap::Capture::from_device(src_dev.clone())?
        .immediate_mode(true)
        .open()?;

    hw_cap.filter("dst 255.255.255.255 and udp", true)?;

    // For weirdos with multiple active VPNs
    let num_of_vpns = split_devices.dst.len();

    // Open all destination devices
    let mut vpn_ipv4_cap: Vec<([u8; 4], Capture<Active>)> = Vec::with_capacity(num_of_vpns);
    for vpn in &split_devices.dst {
        let v = pcap::Capture::from_device((*vpn).clone())?.open()?;
        if let IpAddr::V4(ip4) = vpn.addresses[0].addr {
            vpn_ipv4_cap.push((ip4.octets(), v));
        } else {
            println!("Error: IPv6 VPN address is not supported here.")
        }
    }

    let mut sq = pcap::sendqueue::SendQueue::new(1024 * 1024).unwrap();

    // No panics, unwraps or "?" in this loop. Report failures and proceed to next packet.
    loop {
        let packet = match hw_cap.next_packet() {
            Ok(p) => p,
            Err(e) => {
                println!("Error while receiving packet: {}", e);
                continue;
            }
        };
        let packet_len = packet.header.len as usize;
        for (ip4, vcap) in &mut vpn_ipv4_cap {
            let mut pktbuf: [u8; 1514] = [0u8; 1514];
            pktbuf[0..packet_len].copy_from_slice(packet.data);
            pktbuf[26..30].copy_from_slice(ip4);

            if !BROADCAST {
                unimplemented!("Modify dst IP");
            }

            // This code looks simpler, but doesn't work:
            // Error while resending packet: libpcap error: send error: PacketSendPacket failed: A device attached to the system is not functioning.  (31)
            // if let Err(e) = vcap.sendpacket(&pktbuf[0..packet_len]) {
            //     println!("Error while resending packet: {}", e);
            // }

            if let Err(e) = sq.queue(None, &pktbuf[0..packet_len]) {
                println!("Error while adding packet to the queue: {}", e);
                continue;
            }
            if let Err(e) = sq.transmit(vcap, pcap::sendqueue::SendSync::Off) {
                println!("Error while transmitting packet: {}", e);
                continue;
            }
        }
    }
}
