# vpnparty

A LAN party via VPN.

## How it works

There are 3 main steps:

1. Announcement. vpnparty notifies whole VPN network that you want to play.
2. Discovery. vpnparty listens to replies. There should be a second computer willing to join the game.
3. Retransmission. Once at least one peer discovered, vpnparty starts retransmitting broadcast packets the peer(s).

There are two mechanisms for announcement/discovery working simultaneously:

- multicast. Efficient and nice way to discover peer.
  - Advantage - announcement is the single packet. Minimalistic.
  - Disadvantage - network requires additional configuration to support multicast packets. Multicast is not available in VPNs by default and most likely disabled in your case.
- UDP. Raw brute force. Announcement step sends packet to every IP address in range 255.255.255.0. If your peers are there, connection will be established.
  - Advantage - works.
  - Disadvantage - spams network with 255 packets (only once!).

Retransmission is simple. Capture broadcast packets using `Npcap`, replace broadcast IP address by peer IP address, send. Repeat for every peer.

## How to use

1. Download and install latest [Npcap](https://npcap.com/#download). Tested with versions 1.79 and 1.80. Any compatible should fit.
**Important!** Select `Install Npcap in WinPcap API-compatible Mode` checkbox!
2. Compile (or get somewhere) binaries. See instruction below.
3. Add vpnparty to your firewall exceptions. It needs UDP ports 54928 and 54929 by default.
4. Run vpnparty without arguments. Just double-click. Should work as is.

### CLI options

You can adapt application behavior to your needs. Let's see some examples:

`.\vpnparty --help` shows detailed help message with examples.

`.\vpnparty -b 10.0.0.15 10.0.0.22` manually specify peer IP addresses.

`.\vpnparty -b 10.0.0.15 10.0.0.22 --no-multicast --no-udping` if you know all your peers (let's say there are 3 players), feel free to disable both discovery mechanisms as redundant.

`.\vpnparty --monochrome` is useful if your command line doesn't support color output.

`.\vpnparty -p 7654` retransmits only broadcast packets with destination port 7654. Useful if you know exact port that your game uses. By default all broadcast packets are retransmitted, which might be not desired. One more option is `-p known`, which is the synonym to `-p 4549 6112 42801`. See those ports below.

`.\vpnparty -v=1` to see debug messages. Set `-v=2` to see all processed packets. Useful for debug.

## How to compile

```bash
git clone <REPO>
cd vpnparty
cargo build --release
cargo clippy
```

Compilation takes around 7 seconds. `target\release` will contain `generator.exe` and `vpnparty.exe`.

- generator.exe is the debug tool. It sends 2 broadcast packets (to ports 4549 and 6112) every second. See troubleshooting section for details.
- vpnparty.exe is the application that you need.

## Troubleshoot

## Acknowledgements

Thanks [Ratmir Karabut](https://github.com/rkarabut) and his [udp-broadcast-tunnel](https://github.com/rkarabut/udp-broadcast-tunnel) for inspiration.

## License

GNU GPLv3