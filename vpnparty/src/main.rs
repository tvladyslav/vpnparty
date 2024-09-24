use pcap::{Active, Address, Capture, ConnectionStatus, Device};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
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

const HELP: &str = "\
vpnparty is a next gen LAN party.

USAGE:
  vpnparty [FLAGS] [OPTIONS]

FLAGS:
  -h, --help              Prints help information
  --devices               List available network adapters
  --monochrome            Don't use colors in output

OPTIONS:
  -v, --verbose  NUMBER   Verbosity level [0-3].
  -s, --srcdev   NAME     Name of the device, which receives broadcast packets.
                          Usually this is your Ethernet or Wi-Fi adapter, but might be a Hyper-V Virtual adapter.
                          Example: --srcdev=\\Device\\NPF_{D0B8AF5E-B11D-XXXX-XXXX-XXXXXXXXXXXX}
  -d, --dstdevs NAME NAME Space-separated list of your VPN connection devices.
                          Supported VPNs are Wireguard and OpenVPN, altough other should work as well.
                          Example --dstdevs \\Device\\NPF_{CFB8AF5E-A00C-XXXX-XXXX-XXXXXXXXXXXX} \\Device\\NPF_{E1C9B06F-C22E-XXXX-XXXX-XXXXXXXXXXXX}
  -b, --buddyip IP IP     Space-separated list of your teammates IP addresses.
                          Usually statically assigned in Wireguard/OpenVPN configuration.
                          Example: --buddyip 10.2.0.5 10.2.0.6 10.2.0.9 10.2.0.15
";

struct ParsedDevices<'v> {
    src: Option<&'v Device>,
    dst: Vec<&'v Device>,
    virt: Vec<&'v Device>,
}

#[derive(Debug)]
struct Arguments {
    _srcdev: Option<String>,
    dstdevs: Vec<String>,
    buddyip: Vec<Ipv4Addr>,
}

/// Parse command line arguments
fn parse_args() -> Result<Arguments, String> {
    use lexopt::prelude::*;

    let max_verbosity = 3u8;

    let mut srcdev: Option<String> = None;
    let mut dstdevs: Vec<String> = Vec::new();
    let mut buddyip: Vec<Ipv4Addr> = Vec::new();

    let mut parser = lexopt::Parser::from_env();
    while let Some(arg) = parser.next().map_err(|e| e.to_string())? {
        match arg {
            Short('v') | Long("verbose") => {
                let verbosity: u8 = parser
                    .value()
                    .map_err(|e| e.to_string())?
                    .parse::<u8>()
                    .map_err(|e| e.to_string())?;
                logger::set_verbosity(std::cmp::min(verbosity, max_verbosity));
            }
            Short('s') | Long("srcdev") => {
                let s = parser
                    .value()
                    .map_err(|e| e.to_string())?
                    .string()
                    .map_err(|e| format!("Invalid device name {:?}.", e))?;
                if !s.starts_with("\\Device\\NPF_{") || !s.ends_with("}") {
                    return Err(format!("Invalid device name {}.", s));
                }
                srcdev = Some(s);
            }
            Short('d') | Long("dstdevs") => {
                for d in parser.values().map_err(|e| e.to_string())? {
                    let s = d
                        .string()
                        .map_err(|e| format!("Invalid device name {:?}.", e))?;
                    if !s.starts_with("\\Device\\NPF_{") || !s.ends_with("}") {
                        return Err(format!("Invalid device name {}.", s));
                    }
                    dstdevs.push(s);
                }
            }
            Short('b') | Long("buddyip") => {
                for ipstr in parser.values().map_err(|e| e.to_string())? {
                    let s = ipstr
                        .string()
                        .map_err(|e| format!("Failed to parse an IP address {:?}", e))?;
                    let a = Ipv4Addr::from_str(&s).map_err(|e| e.to_string())?;
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
            _ => return Err("Unexpected command line option.".to_string()),
        }
    }

    Ok(Arguments {
        _srcdev: srcdev,
        dstdevs,
        buddyip,
    })
}

/// Get list of all network adapters and filter out useless.
fn get_promising_devices() -> Result<Vec<Device>, String> {
    let devs = pcap::Device::list().map_err(|e| e.to_string())?;
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

fn verify_devices<'r>(pd: &'r ParsedDevices) -> Result<&'r Device, String> {
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
        return Err(
            "Can't find your VPN connection. Please specify it manually via CLI.".to_string(),
        );
    }
    let src_dev = match pd.src {
        None => {
            return Err(
                "Can't find your HW network adapter. Please specify it manually via CLI."
                    .to_string(),
            );
        }
        Some(s) => s,
    };
    Ok(src_dev)
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

fn main() -> Result<(), String> {
    let args: Arguments = parse_args()?;

    debug!("{:?}", args);

    // TODO: CLI option to disable this heuristic
    let devs: Vec<Device> = get_promising_devices()?;
    let split_devices: ParsedDevices = split_to_src_and_dst(&devs);
    // TODO: more granular verification
    let src_dev: &Device = verify_devices(&split_devices)?;

    // Setup Capture
    // TODO: capture virtual devices as well?
    let mut hw_cap = pcap::Capture::from_device(src_dev.clone())
        .map_err(|e| e.to_string())?
        .immediate_mode(true)
        .open()
        .map_err(|e| e.to_string())?;

    hw_cap
        .filter("dst 255.255.255.255 and udp", true)
        .map_err(|e| e.to_string())?;

    // For weirdos with multiple active VPNs
    let num_of_vpns = split_devices.dst.len();

    // Open all destination devices
    let mut vpn_ipv4_cap: Vec<([u8; 4], Capture<Active>)> = Vec::with_capacity(num_of_vpns);
    for vpn in &split_devices.dst {
        let v = pcap::Capture::from_device((*vpn).clone())
            .map_err(|e| e.to_string())?
            .open()
            .map_err(|e| e.to_string())?;
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

            //TODO: use only IPs that belongs to this device
            for dstip in &args.buddyip {
                if *ip4 == dstip.octets() {
                    // TODO: Come ON!!!
                }
                no_ether_pktbuf[16..20].copy_from_slice(&dstip.octets());

                if rewrite_ip4_checksum(&mut no_ether_pktbuf[0..20]).is_err() {
                    critical!("Should never happen! Checksum calculation error.");
                    continue;
                }

                //TODO: UDP checksum (optional)

                trace!("{:?}", no_ether_pktbuf);

                if let Err(e) = vcap.sendpacket(&mut *no_ether_pktbuf) {
                    error!("Error while resending packet: {}", e);
                }
            }
        }
    }
}
