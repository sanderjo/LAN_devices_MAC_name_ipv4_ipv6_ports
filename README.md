# LAN devices: MAC, name, IPv4, IPv6, ports

A single Python script that lists the devices on your local network in a table:
MAC address, likely name, OUI vendor, IPv4 address(es), public IPv6 address(es)
and, optionally, open TCP ports.

Linux only. No root needed, and no Python packages outside the standard library.

## Example

```
$ ./LAN_devices_MAC_name_ipv4_ipv6_ports.py -p 80,443,8080
MAC                Name                               Vendor                  IPv4            Public IPv6                              Open ports
-----------------  ---------------------------------  ----------------------  --------------  ---------------------------------------  -------------
1c:53:f9:03:6b:0c  Huiskamer chromecast (Chromecast)  Google, Inc.            192.168.1.16    2001:1234:abcd:a800:4991:25a4:a10d:9c40
                                                                                              2001:1234:abcd:a800:6121:2146:7be3:604a
02:01:9c:45:40:d7  nanopineo2                         (random MAC)            192.168.1.109   2001:1234:abcd:a800:8f3d:c201:3756:a4dc  80, 443, 8080
7c:76:35:ab:d1:81  x360 [this host]                   Intel Corporate         192.168.1.235   2001:1234:abcd:a800:4a82:6589:cb33:3456  80, 8080
ec:fc:2f:47:e7:6b  [gateway]                          Sagemcom Broadband SAS  192.168.1.254   2001:1234:abcd:a800:eefc:2fff:fe47:e76b  80, 443
```

`example_output.txt` has a full run.

## Requirements

- Linux with `iproute2` (`ip`), `ping` and `getent`
- Python 3
- Optional: `avahi-utils` (`avahi-browse`, `avahi-resolve`) for mDNS names
- Optional: `ieee-data` (`/usr/share/ieee-data/oui.csv`, `mam.csv`, `oui36.csv`) for vendor names

On Debian/Ubuntu:

```
sudo apt install iproute2 iputils-ping avahi-utils ieee-data
```

The packaged vendor lists can be a year or more old. To fetch the current ones from the IEEE, so recently assigned MAC prefixes get a vendor name:

```
sudo update-ieee-data
```

## Usage

```
./LAN_devices_MAC_name_ipv4_ipv6_ports.py [-i IFACE] [-w SECONDS] [-p PORTS] [-t SECONDS]
```

| Option | Description |
|---|---|
| `-i`, `--interface` | Interface to scan. Default: the physical NIC of the default route |
| `-w`, `--wait` | Seconds to wait for ARP/NDP replies (default 3) |
| `-p`, `--ports` | TCP ports to probe, e.g. `80,8080` or `8000-8010`. Omit to skip the port scan |
| `-t`, `--port-timeout` | Seconds per TCP connect attempt (default 1) |

The table goes to stdout. Status lines (interface, device count) go to stderr.

## How it works

1. **Interface**: picks the default-route interface, preferring physical NICs over tunnels and bridges.
2. **IPv4 discovery**: sends an empty UDP datagram to every address in the subnet, so the kernel does ARP. Subnets larger than a /22 are limited to the /22 around your own address.
3. **IPv6 discovery**: pings `ff02::1` (all nodes), sends datagrams to the EUI-64 address each known MAC would have in your /64, and to the IPv6 addresses advertised over mDNS.
4. **Neighbour table**: reads `ip neigh` and groups addresses by MAC. Only global IPv6 addresses are shown. Devices with only a link-local address are still listed.
5. **Names**, in order of preference: own hostname, mDNS hostname, IPv4 reverse DNS, mDNS friendly name (`fn`), mDNS service name, model (`md`), IPv6 reverse DNS (LAN names only, not ISP PTR records). Generic names such as UUIDs are skipped.
6. **Vendor**: looks up the MAC in the IEEE MA-S, MA-M and MA-L registries. Locally administered MACs show as `(random MAC)`, unknown ones as `?`.
7. **Ports**: optional TCP connect scan, on IPv4 or on IPv6 if the device has no IPv4.

## Notes

- `[this host]` and `[gateway]` mark your own machine and the default router.
- An IPv4 address with `*` came from mDNS only. A host with several NICs on the LAN may answer ARP for all its addresses from one NIC ("ARP flux"), which leaves the other MAC without an IPv4 address in the neighbour table.
- Devices that block ARP/NDP or have been asleep for a while may not show up. Run the script again, or raise `--wait`.
- Only scan networks you are allowed to scan.
