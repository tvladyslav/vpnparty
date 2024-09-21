use pcap::{ConnectionStatus, Device};
use std::io::ErrorKind;
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
    let devs = get_promising_devices()?;
    // TODO: CLI to disable prints
    print_devices(&devs);

    // TODO: CLI option to disable this heuristic
    let split_devices = split_to_src_and_dst(&devs);
    let src_dev: &Device = verify_devices(&split_devices)?;

    // Setup Capture
    let mut cap = pcap::Capture::from_device(src_dev.clone())?
        .immediate_mode(true)
        .open()?;

    cap.filter("dst 255.255.255.255 and udp", true)?;

    let mut count = 0;
    cap.for_each(None, |packet| {
        println!("{} Got {:?}", count, packet.header);
        count += 1;
        // if count > 10 {
        //     panic!("ow");
        // }
    })?;
    Ok(())
}
