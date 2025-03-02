use std::{net::Ipv4Addr, str::FromStr};

use pcap::Device;

use crate::{e, logger};
use crate::network_devices::{get_promising_devices, print_devices};

const HELP: &str = "\
vpnparty is a next gen LAN party.

USAGE:
  vpnparty [FLAGS] [OPTIONS]

FLAGS:
  -h, --help              Prints help information
  --devices               List available network adapters
  --monochrome            Don't use colors in output
  --no-multicast          Disable multicast discovery
  --no-udping             Disable ping discovery

OPTIONS:
  -v, --verbose  NUMBER        Verbosity level [0-2] where 1 is debug and 2 trace level.
  -s, --srcdev   \"NAME\"        Name of the device, which receives broadcast packets.
                               Usually this is your Ethernet or Wi-Fi adapter, but might be a Hyper-V Virtual adapter.
                               Example: --srcdev=\"\\Device\\NPF_{D0B8AF5E-B11D-XXXX-XXXX-XXXXXXXXXXXX}\"
  -d, --dstdev \"NAME\" \"NAME\"   Space-separated list of your VPN connection devices.
                               Supported VPNs are Wireguard and OpenVPN, altough other should work as well.
                               Example --dstdev \"\\Device\\NPF_{CFB8AF5E-A00C-XXXX-XXXX-XXXXXXXXXXXX}\" \"\\Device\\NPF_{E1C9B06F-C22E-XXXX-XXXX-XXXXXXXXXXXX}\"
  -b, --buddyip IP IP          Space-separated list of your teammates IP addresses.
                               Usually statically assigned in Wireguard/OpenVPN configuration.
                               Example: --buddyip 10.2.0.5 10.2.0.6 10.2.0.9 10.2.0.15
  -p, --port PORT PORT         Capture broadcast packets only for given ports. Predefined constants are \"all\" (default) and \"known\".
                               Example: -p 4549 6112 42801
                               Example: -p known
  --mip IP                     Specify custom multicast IP (default is 239.1.2.3). Must be same for all buddies.
                               Must belong to the multicast range! Best option is 239.*.*.* range.
                               Example: --mip 239.240.241.242
  --mport PORT                 Specify custom multicast port (default is 54929). Must be same for all buddies.
                               Example: --mport 61111
  --uport PORT                 Specify custom udp discovery port (default is 54928). Must be same for all buddies.
                               Example: --uport 61112
";

const KNOWN_PORTS: [u16; 3] = [
    4549,   // Torchlight 2
    6112,   // Warcraft 3
    42801,  // Titan Quest
];

/// Command line arguments
#[derive(Debug)]
pub struct Arguments {
    pub srcdev: Option<String>,
    pub dstdev: Vec<String>,
    pub buddyip: Vec<Ipv4Addr>,
    pub port: Vec<u16>,
    pub mip: Option<Ipv4Addr>,
    pub mport: Option<u16>,
    pub uport: Option<u16>,
    pub no_multicast: bool,
    pub no_udping: bool,
}

/// Parse command line arguments
pub fn parse_args() -> Result<Arguments, String> {
    use lexopt::prelude::*;

    let max_verbosity = 3u8;
    let dev_name_len = 50;

    let mut srcdev: Option<String> = None;
    let mut dstdev: Vec<String> = Vec::new();
    let mut buddyip: Vec<Ipv4Addr> = Vec::new();
    let mut port: Vec<u16> = Vec::new();
    let mut mip: Option<Ipv4Addr> = None;
    let mut mport: Option<u16> = None;
    let mut uport: Option<u16> = None;
    let mut no_multicast: bool = false;
    let mut no_udping: bool = false;

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
            Short('d') | Long("dstdev") => {
                for d in e!(parser.values()) {
                    let s = e!(d.string());
                    if !s.starts_with("\\Device\\NPF_{")
                        || !s.ends_with("}")
                        || s.len() != dev_name_len
                    {
                        return Err(format!("Invalid device name {}.", s));
                    }
                    dstdev.push(s);
                }
            }
            Short('b') | Long("buddyip") => {
                for ipstr in e!(parser.values()) {
                    let s = e!(ipstr.string());
                    let a = e!(Ipv4Addr::from_str(&s));
                    buddyip.push(a);
                }
            }
            Short('p') | Long("port") => {
                for portstr in e!(parser.values()) {
                    let s: String = e!(portstr.string());
                    match s.as_str() {
                        "all" => {
                            port.clear();
                            break;          // Empty vector means any port
                        },
                        "known" => {
                            port = KNOWN_PORTS.to_vec();
                            break;
                        },
                        _ => {
                            let p = e!(s.parse::<u16>());
                            port.push(p);
                        }
                    }
                }
            }
            Long("mip") => {
                let s = e!(e!(parser.value()).string());
                let a = e!(Ipv4Addr::from_str(&s));
                mip = Some(a);
            }
            Long("mport") => {
                let port: u16 = e!(e!(parser.value()).parse::<u16>());
                mport = Some(port);
            }
            Long("uport") => {
                let port: u16 = e!(e!(parser.value()).parse::<u16>());
                uport = Some(port);
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
            Long("no-multicast") => {
                no_multicast = true;
            }
            Long("no-udping") => {
                no_udping = true;
            }
            _ => return Err(format!("Unexpected command line option {:?}.", arg)),
        }
    }

    Ok(Arguments {
        srcdev,
        dstdev,
        buddyip,
        port,
        mip,
        mport,
        uport,
        no_multicast,
        no_udping
    })
}
