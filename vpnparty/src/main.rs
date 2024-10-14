use pcap::{Active, Address, Capture, ConnectionStatus, Device};
use std::net::{IpAddr, Ipv4Addr};
use std::ops::BitAnd;
use std::str::FromStr;
use std::sync::mpsc;
use std::thread;
use std::vec::Vec;

mod broadcast_listener;
use broadcast_listener::{listen_broadcast, Bpacket};
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

const HELP: &str = "\
vpnparty is a next gen LAN party.

USAGE:
  vpnparty [FLAGS] [OPTIONS]

FLAGS:
  -h, --help              Prints help information
  --devices               List available network adapters
  --monochrome            Don't use colors in output

OPTIONS:
  -v, --verbose  NUMBER        Verbosity level [0-3].
  -s, --srcdev   \"NAME\"        Name of the device, which receives broadcast packets.
                               Usually this is your Ethernet or Wi-Fi adapter, but might be a Hyper-V Virtual adapter.
                               Example: --srcdev=\"\\Device\\NPF_{D0B8AF5E-B11D-XXXX-XXXX-XXXXXXXXXXXX}\"
  -d, --dstdevs \"NAME\" \"NAME\"  Space-separated list of your VPN connection devices.
                               Supported VPNs are Wireguard and OpenVPN, altough other should work as well.
                               Example --dstdevs \"\\Device\\NPF_{CFB8AF5E-A00C-XXXX-XXXX-XXXXXXXXXXXX}\" \"\\Device\\NPF_{E1C9B06F-C22E-XXXX-XXXX-XXXXXXXXXXXX}\"
  -b, --buddyip IP IP          Space-separated list of your teammates IP addresses.
                               Usually statically assigned in Wireguard/OpenVPN configuration.
                               Example: --buddyip 10.2.0.5 10.2.0.6 10.2.0.9 10.2.0.15
";

/// Devices that are parsed by internal heuristic, may be overridden by user
struct PromisingDevices {
    src: Option<Device>,
    dst: Vec<Device>,
    virt: Vec<Device>,
}

/// Verified and ready-to-go devices
#[derive(Debug)]
struct ParsedDevices {
    src: Device,
    dst: Vec<Device>,
}

/// Command line arguments
#[derive(Debug)]
struct Arguments {
    srcdev: Option<String>,
    dstdevs: Vec<String>,
    buddyip: Vec<Ipv4Addr>,
}

/// VPN device and related destination IPs
struct Direction {
    vpnip: Ipv4Addr,
    vpncap: Capture<Active>,
    buddyip: Vec<Ipv4Addr>,
}

/// Macro to cast any error type to String
/// //TODO: verify
#[macro_export]
macro_rules! e {
    ($($arg:tt)+) => ($($arg)+.map_err(|e| e.to_string())?)
}

/// Parse command line arguments
fn parse_args() -> Result<Arguments, String> {
    use lexopt::prelude::*;

    let max_verbosity = 3u8;
    let dev_name_len = 50;

    let mut srcdev: Option<String> = None;
    let mut dstdevs: Vec<String> = Vec::new();
    let mut buddyip: Vec<Ipv4Addr> = Vec::new();

    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = e!(parser.next()) {
        match arg {
            Short('v') | Long("verbose") => {
                let verbosity: u8 = e!(e!(parser.value()).parse::<u8>());
                logger::set_verbosity(std::cmp::min(verbosity, max_verbosity));
            }
            Short('s') | Long("srcdev") => {
                let s = e!(e!(parser.value()).string());
                if !s.starts_with("\\Device\\NPF_{") || !s.ends_with("}") || s.len() != dev_name_len
                {
                    return Err(format!("Invalid device name {}.", s));
                }
                srcdev = Some(s);
            }
            Short('d') | Long("dstdevs") => {
                for d in e!(parser.values()) {
                    let s = e!(d.string());
                    if !s.starts_with("\\Device\\NPF_{")
                        || !s.ends_with("}")
                        || s.len() != dev_name_len
                    {
                        return Err(format!("Invalid device name {}.", s));
                    }
                    dstdevs.push(s);
                }
            }
            Short('b') | Long("buddyip") => {
                for ipstr in e!(parser.values()) {
                    let s = e!(ipstr.string());
                    let a = e!(Ipv4Addr::from_str(&s));
                    buddyip.push(a);
                }
            }
            Short('h') | Long("help") => {
                println!("{}", HELP);
                std::process::exit(0);
            }
            Long("devices") => {
                let devs: Vec<Device> = get_promising_devices()?;
                print_devices(&devs);
                std::process::exit(0);
            }
            Long("monochrome") => {
                crate::logger::set_monochrome();
            }
            _ => return Err(format!("Unexpected command line option {:?}.", arg)),
        }
    }

    Ok(Arguments {
        srcdev,
        dstdevs,
        buddyip,
    })
}

/// Get list of all network adapters and filter out useless.
fn get_promising_devices() -> Result<Vec<Device>, String> {
    let devs = e!(pcap::Device::list());
    let filtered = devs
        .into_iter()
        .filter(|d| {
            d.flags.is_up()
                && !d.flags.is_loopback()
                && !d.addresses.is_empty()
                && d.flags.connection_status == ConnectionStatus::Connected
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

/// Consume devices and decide which device provides broadcast packets and which needs them
fn split_to_src_and_dst(full_list: Vec<Device>) -> PromisingDevices {
    let dst: Vec<Device> = full_list
        .iter()
        .filter(|d| contains(d, VPN_NAMES))
        .cloned()
        .collect();
    let virt: Vec<Device> = full_list
        .iter()
        .filter(|d| contains(d, VIRT_NAMES))
        .cloned()
        .collect();
    let src: Option<Device> = full_list.iter().find(|d| contains(d, HW_NAMES)).cloned();
    if src.is_none() {
        let guess = full_list.iter().find(|d| !contains(d, VPN_NAMES)).cloned();
        return PromisingDevices {
            src: guess,
            dst,
            virt,
        };
    }

    PromisingDevices { src, dst, virt }
}

fn print_devices(devs: &[Device]) {
    if crate::logger::is_monochrome() {
        println!(
            "Network adapter name                                IP address       Description"
        );
    } else {
        println!("\x1b[32mNetwork adapter name                                IP address       Description\x1b[0m");
    }
    for dev in devs {
        let ip_opt: &Option<&Address> = &dev.addresses.iter().find(|a| a.addr.is_ipv4());
        if let Some(ip) = ip_opt {
            let row = format!(
                "{0}  {1:W$}  {2}",
                dev.name,
                ip.addr.to_string(),
                dev.desc.clone().unwrap_or_default(),
                W = 15
            );
            println!("{}", row);
        }
    }
}

fn rewrite_ip4_checksum(buf: &mut [u8]) -> Result<(), String> {
    if buf.len() != 20 {
        return Err("Incorrect packet header length.".to_string());
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

fn show_virt_dev_warning(virt: &[Device]) {
    if !virt.is_empty() {
        warn!("There are active virtual network adapters in your system.");
        warn!("To prevent troubles either disable virtual adapters or specify the correct HW adapter via command line.");
        warn!("Here are PowerShell commands (run as Administrator):");
        for vd in virt {
            warn!(
                "\tDisable-NetAdapter -InterfaceDescription  \"{}\"",
                vd.desc.clone().unwrap()
            );
        }
        warn!("Feel free to enable them back using following PowerShell commands:");
        for vd in virt {
            warn!(
                "\tEnable-NetAdapter -InterfaceDescription  \"{}\"",
                vd.desc.clone().unwrap()
            );
        }
    }
}

/// Verify CLI arguments. Fill gaps.
fn get_devices(a: &Arguments) -> Result<ParsedDevices, String> {
    let devs: Vec<Device> = get_promising_devices()?;
    let split_devices: PromisingDevices = split_to_src_and_dst(devs.clone());
    show_virt_dev_warning(&split_devices.virt);

    let src: Device = match &a.srcdev {
        // No src device specified in CLI, let's do our best to find some in our list
        None => split_devices.src.ok_or(
            "Can't find your HW network adapter. Please specify it manually via CLI.".to_string(),
        )?,

        // User specified an adapter via CLI, let's find it in our list
        Some(name) => devs
            .iter()
            .find(|d| d.name == *name)
            .ok_or(format!("Can't find {} network adapter.", name))?
            .clone(),
    };

    let dst: Vec<Device> = if a.dstdevs.is_empty() {
        if split_devices.dst.is_empty() {
            return Err(
                "Can't find your VPN connection. Please specify it manually via CLI.".to_string(),
            );
        } else {
            split_devices.dst
        }
    } else {
        let result: Vec<Device> = devs
            .iter()
            .filter_map(|d| {
                for v in &a.dstdevs {
                    if d.name == *v {
                        return Some(d.clone());
                    }
                }
                None
            })
            .collect();
        if result.len() != a.dstdevs.len() {
            error!("Can't find all provided VPN devices.");
            if !result.is_empty() {
                error!("Devices, which are found:");
                for r in result {
                    error!("\t{}", r.name);
                }
            }
            return Err("VPN devices not found.".to_string());
        } else {
            result
        }
    };
    Ok(ParsedDevices { src, dst })
}

/// Open all destination devices
fn open_dst_devices(
    devices: ParsedDevices,
    buddyip_slice: &[Ipv4Addr],
) -> Result<Vec<Direction>, String> {
    if let IpAddr::V4(ip4) = &devices.src.addresses[0].addr {
        if buddyip_slice.contains(ip4) {
            critical!(
                "You specified {} as buddy address but it is actually your address.",
                ip4
            );
            return Err(format!("Wrong buddy address {}", ip4));
        }
    }

    let mut buddyip: Vec<Ipv4Addr> = buddyip_slice.to_vec();

    // For weirdos with multiple active VPNs
    let num_of_vpns = devices.dst.len();
    let mut vpn_ipv4_cap: Vec<Direction> = Vec::with_capacity(num_of_vpns);
    for vpn in &devices.dst {
        let addresses = &vpn.addresses[0];
        if let IpAddr::V4(ip4) = addresses.addr {
            // TODO: hardcode here because my Wireguard provides 255.255.255.255
            let vpnmask: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);
            let precalc: Ipv4Addr = ip4.bitand(vpnmask);
            let buddy_in_this_direction: Vec<Ipv4Addr> = buddyip
                .iter()
                .filter(|buddy| precalc == buddy.bitand(vpnmask))
                .cloned()
                .collect();

            // Is there buddy IP on this VPN connection?
            if buddy_in_this_direction.is_empty() {
                warn!(
                    "There are no buddy IP addresses that belongs to {} device with IP {} and netmask {}.", &vpn.name, ip4, vpnmask
                );
                warn!("Your buddy IP list is {:?}", &buddyip);
            }

            // Check for intersection between buddy and own IPs
            if buddy_in_this_direction.contains(&ip4) {
                critical!(
                    "You specified {} as buddy address but it is actually your address.",
                    ip4
                );
                return Err(format!("Wrong buddy address {}", ip4));
            }

            // Remove used addresses from general list
            buddyip = buddyip
                .iter()
                .filter(|b| !buddy_in_this_direction.contains(b))
                .cloned()
                .collect();

            let v = e!(e!(pcap::Capture::from_device((*vpn).clone())).open());
            vpn_ipv4_cap.push(Direction {
                vpnip: ip4,
                vpncap: v,
                buddyip: buddy_in_this_direction,
            });
        } else {
            critical!("Error: IPv6 VPN address is not supported here.");
            return Err("IPv6 VPN address is not supported here.".to_string());
        }
    }
    if !buddyip.is_empty() {
        critical!("Those IP addresses {:?} does not belong to any known VPN connection. Either correct IP address or specify a VPN connection via CLI.", buddyip);
        return Err("Redundant buddy IP.".to_string());
    }
    Ok(vpn_ipv4_cap)
}

fn main() -> Result<(), String> {
    let args: Arguments = parse_args()?;
    debug!("{:?}", args);

    let devices: ParsedDevices = get_devices(&args)?;
    debug!("{:?}", devices);

    //TODO: network discovery for computers on the other side of VPN

    let srcdev: Device = devices.src.clone();
    let mut vpn_ipv4_cap: Vec<Direction> = open_dst_devices(devices, &args.buddyip)?;
    //TODO: debug!()

    //TODO: any-source multicast using Sup! protocol

    let (tx, rx) = mpsc::channel();
    let btx = tx.clone();
    let _broadcast_handle = thread::spawn(move || {
        let _ = listen_broadcast(srcdev, btx);
    });

    // No panics, unwraps or "?" in this loop. Report failures and proceed to next packet.
    loop {
        let packet: Bpacket = match rx.recv() {
            Ok(p) => p,
            Err(e) => {
                error!("Can't receive a packet: {}", e);
                continue;
            }
        };

        // Start from 14th byte to skip Ethernet Frame.
        let no_eth_packet_len = (packet.len - 14) as usize;
        for d in &mut vpn_ipv4_cap {
            let mut pktbuf: [u8; 1514] = [0u8; 1514];
            let no_ether_pktbuf: &mut [u8] = &mut pktbuf[0..no_eth_packet_len];

            // Rewrite source and destination IPs
            no_ether_pktbuf.copy_from_slice(&packet.data[14..]);
            no_ether_pktbuf[12..16].copy_from_slice(&d.vpnip.octets());

            for dstip in &d.buddyip {
                no_ether_pktbuf[16..20].copy_from_slice(&dstip.octets());

                if rewrite_ip4_checksum(&mut no_ether_pktbuf[0..20]).is_err() {
                    critical!("Should never happen! Checksum calculation error.");
                    continue;
                }

                //TODO: UDP checksum (optional)

                trace!("{:?}", no_ether_pktbuf);

                if let Err(e) = d.vpncap.sendpacket(&mut *no_ether_pktbuf) {
                    error!("Error while resending packet: {}", e);
                }
            }
        }
    }
    // e!(broadcast_handle.join());
}
