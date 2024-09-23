use clap::{ArgAction, Parser};
use pcap::{Active, Capture, ConnectionStatus, Device};
use std::io::ErrorKind;
use std::net::IpAddr;
use std::vec::Vec;

mod logger;

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

#[derive(Parser, Default, Debug)]
struct Arguments {
    #[clap(short = 'v', long = "verbose", action = ArgAction::Count)]
    verbosity: u8,
}

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
                    .contains("VirtualBox") // TODO: test
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
        warn!("There are active virtual network adapters in your system.");
        warn!("To prevent troubles either disable virtual adapters or specify the correct HW adapter via command line.");
        warn!("Here are PowerShell commands (run as Administrator):");
        for vd in &pd.virt {
            warn!(
                "\tDisable-NetAdapter -InterfaceDescription  \"{}\"",
                vd.desc.clone().unwrap()
            );
        }
        warn!("Feel free to enable them back using following PowerShell commands:");
        for vd in &pd.virt {
            warn!(
                "\tEnable-NetAdapter -InterfaceDescription  \"{}\"",
                vd.desc.clone().unwrap()
            );
        }
        // This is just a warning, continue execution and hope for best.
    }
    if pd.dst.is_empty() {
        critical!("Can't find your VPN connection.");
        critical!("Please specify it manually via CLI.");
        return Err(pcap::Error::IoError(ErrorKind::NotFound));
    }
    let src_dev = match pd.src {
        None => {
            critical!("Can't find your HW network adapter.");
            critical!("Please specify it manually via CLI.");
            return Err(pcap::Error::IoError(ErrorKind::NotFound));
        }
        Some(s) => s,
    };
    Ok(src_dev)
}

fn print_devices(devs: &[Device]) {
    info!("Devices:");
    for dev in devs {
        info!("{0}\t{1}", dev.name, dev.desc.clone().unwrap_or_default());
        for a in &dev.addresses {
            info!("\t{0}", a.addr);
        }
    }
}

fn rewrite_ip4_checksum(buf: &mut [u8]) -> Result<(), pcap::Error> {
    if buf.len() != 20 {
        return Err(pcap::Error::IoError(ErrorKind::Other));
    }
    buf[10] = 0u8;
    buf[11] = 0u8;
    let checksum: u16 = calculate_ip4_checksum(buf);
    buf[10] = (checksum >> 8) as u8;
    buf[11] = (checksum & 0xFF) as u8;
    Ok(())
}

fn calculate_ip4_checksum(buf: &[u8]) -> u16 {
    let sum: usize = buf
        .chunks(2)
        .map(|c| ((c[0] as usize) << 8) + (c[1] as usize))
        .sum();
    let carry: usize = sum >> 16;
    let checksum: u16 = !(((sum & 0xFFFF) + carry) as u16);
    checksum
}

#[test]
fn ip4_checksum() {
    #[rustfmt::skip]
    let input: [u8; 20] = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
        0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ];
    let given_checksum = calculate_ip4_checksum(&input);
    let expected_checksum: u16 = 0xb861u16;
    assert_eq!(given_checksum, expected_checksum);
}

fn main() -> Result<(), pcap::Error> {
    let args = Arguments::parse();
    logger::set_verbosity(args.verbosity);

    debug!("{:?}", args);

    let devs: Vec<Device> = get_promising_devices()?;
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
            critical!("Error: IPv6 VPN address is not supported here.")
        }
    }

    //TODO: network discovery for computers on the other side of VPN

    // No panics, unwraps or "?" in this loop. Report failures and proceed to next packet.
    loop {
        let packet = match hw_cap.next_packet() {
            Ok(p) => p,
            Err(e) => {
                error!("Error while receiving packet: {}", e);
                continue;
            }
        };

        if packet.header.len < 42 {
            error!("This packet is empty, skipping.");
            continue;
        }

        // Start from 14th byte to skip Ethernet Frame.
        let no_eth_packet_len = (packet.header.len - 14) as usize;
        for (ip4, vcap) in &mut vpn_ipv4_cap {
            let mut pktbuf: [u8; 1514] = [0u8; 1514];
            let no_ether_pktbuf: &mut [u8] = &mut pktbuf[0..no_eth_packet_len];

            // Rewrite source and destination IPs
            no_ether_pktbuf.copy_from_slice(&packet.data[14..]);
            no_ether_pktbuf[12..16].copy_from_slice(ip4);
            no_ether_pktbuf[16..20].copy_from_slice(&[10, 0, 0, 2]); //TODO!!!

            if rewrite_ip4_checksum(&mut no_ether_pktbuf[0..20]).is_err() {
                critical!("Should never happen! Checksum calculation error.");
                continue;
            }

            //TODO: UDP checksum (optional)

            trace!("{:?}", no_ether_pktbuf);

            if let Err(e) = vcap.sendpacket(no_ether_pktbuf) {
                error!("Error while resending packet: {}", e);
            }
        }
    }
}
