use std::{net::{IpAddr, Ipv4Addr}, ops::BitAnd};

use pcap::{Address, ConnectionStatus, Device};

use crate::{cli_parser, critical, debug, e, error, warn, Direction};

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

/// Devices that are parsed by internal heuristic, may be overridden by user
struct PromisingDevices {
    src: Option<Device>,
    dst: Vec<Device>,
    virt: Vec<Device>,
}

/// Verified and ready-to-go devices
#[derive(Debug)]
pub struct ParsedDevices {
    pub src: Device,
    pub dst: Vec<Device>,
}

/// Get list of all network adapters and filter out useless.
pub fn get_promising_devices() -> Result<Vec<Device>, String> {
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

pub fn print_devices(devs: &[Device]) {
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

/// Verify CLI arguments. Fill gaps.
pub fn get_devices(a: &cli_parser::Arguments) -> Result<ParsedDevices, String> {
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

    let dst: Vec<Device> = if a.dstdev.is_empty() {
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
                for v in &a.dstdev {
                    if d.name == *v {
                        return Some(d.clone());
                    }
                }
                None
            })
            .collect();
        if result.len() != a.dstdev.len() {
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
pub fn open_dst_devices(
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
                debug!(
                    "There are no buddy IP addresses that belongs to {} device with IP {} and netmask {}.", &vpn.name, ip4, vpnmask
                );
                debug!("Your buddy IP list is {:?}", &buddyip);
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
                // vpndevice: vpn.clone(),
                vpncap: v,
                buddyip: buddy_in_this_direction.into_iter().collect(),
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
