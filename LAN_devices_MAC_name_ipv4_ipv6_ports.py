#!/usr/bin/env python3
"""List the devices on the LAN: MAC, likely name, OUI vendor, IPv4, public IPv6.

Linux only. Works without root: neighbour discovery is triggered by sending
empty UDP datagrams (the kernel then does ARP / NDP for us) and by pinging the
IPv6 all-nodes multicast address. Names come from mDNS (avahi) and reverse DNS.
"""

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time

OUI_FILES = [
    # (path, number of hex digits in the assignment)
    ("/usr/share/ieee-data/oui36.csv", 9),
    ("/usr/share/ieee-data/mam.csv", 7),
    ("/usr/share/ieee-data/oui.csv", 6),
]
LAN_SUFFIXES = (".lan", ".home", ".internal", ".home.arpa", ".localdomain")
MAX_SWEEP_PREFIX = 22  # never sweep more than a /22 (1022 hosts)
# Machine-generated hostnames that say nothing about the device (UUIDs, "Android_<hex>").
GENERIC_HOST_RE = re.compile(r"^(?:.*[_-])?(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})$", re.I)


def run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def ip_json(*args):
    out = run(["ip", "-j", *args])
    return json.loads(out) if out.strip() else []


def is_physical(dev):
    return os.path.exists(f"/sys/class/net/{dev}/device")


def default_interface():
    """Interface of the default route, preferring physical NICs over tunnels/bridges."""
    routes = ip_json("-4", "route", "show", "default") + ip_json("-6", "route", "show", "default")
    routes.sort(key=lambda r: r.get("metric", 0))
    devs = [r["dev"] for r in routes if "dev" in r]
    for dev in devs:
        if is_physical(dev):
            return dev
    if devs:
        return devs[0]
    sys.exit("No default route found.")


def interface_addresses(dev):
    v4, v6 = [], []
    for link in ip_json("addr", "show", "dev", dev):
        for a in link.get("addr_info", []):
            if "local" not in a:
                continue
            iface = ipaddress.ip_interface(f"{a['local']}/{a['prefixlen']}")
            if a["family"] == "inet":
                v4.append(iface)
            elif a["family"] == "inet6" and a.get("scope") == "global":
                v6.append((iface, a.get("temporary", False)))
    return v4, v6


# --- neighbour discovery -------------------------------------------------

def sweep_ipv4(iface):
    net = iface.network
    if net.prefixlen < MAX_SWEEP_PREFIX:
        net = ipaddress.ip_interface(f"{iface.ip}/{MAX_SWEEP_PREFIX}").network
        print(f"note: {iface.network} is large, only sweeping {net}", file=sys.stderr)
    poke(socket.AF_INET, (str(h) for h in net.hosts() if h != iface.ip))


def poke(family, addrs, dev=None):
    """Send an empty UDP datagram to each address so the kernel resolves its MAC."""
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        if dev:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, dev.encode())
            except OSError:
                pass  # needs CAP_NET_RAW on older kernels; routing picks the device anyway
        for a in addrs:
            try:
                s.sendto(b"", (a, 9))  # discard port
            except OSError:
                pass


def ping_all_nodes(dev, sources):
    """Ping ff02::1; with a global source, hosts tend to answer from a global address."""
    cmds = [["ping", "-6", "-c2", "-w3", "-I", str(src), f"ff02::1%{dev}"] for src in sources]
    cmds.append(["ping", "-6", "-c2", "-w3", f"ff02::1%{dev}"])
    procs = [subprocess.Popen(c, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for c in cmds]
    for p in procs:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()


def eui64(prefix_net, mac):
    b = bytearray(bytes.fromhex(mac.replace(":", "")))
    b[0] ^= 0x02
    iid = bytes(b[:3]) + b"\xff\xfe" + bytes(b[3:])
    return str(prefix_net[int.from_bytes(iid, "big")])


def neighbours(dev):
    """{ip_string: mac} for every neighbour entry that has a link-layer address."""
    result = {}
    for n in ip_json("neigh", "show", "dev", dev):
        state = n.get("state", [])
        if "lladdr" in n and not {"FAILED", "INCOMPLETE"} & set(state):
            result[n["dst"]] = n["lladdr"].lower()
    return result


# --- names -----------------------------------------------------------------

def avahi_unescape(s):
    return re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), s)


def avahi_browse(dev):
    """[(address, hostname, service_name, txt_dict)] from resolved mDNS services."""
    out = run(["avahi-browse", "-a", "-r", "-p", "-t"], timeout=15)
    found = []
    for line in out.splitlines():
        f = line.split(";")
        if len(f) < 9 or f[0] != "=" or f[1] != dev:
            continue
        txt = dict(re.findall(r'"([^"=]+)=([^"]*)"', ";".join(f[9:])))
        found.append((f[7], avahi_unescape(f[6]), avahi_unescape(f[3]), txt))
    return found


def avahi_reverse(addr):
    out = run(["avahi-resolve", "-a", addr], timeout=3).split()
    return out[1] if len(out) >= 2 else None


def avahi_forward4(host):
    out = run(["avahi-resolve", "-4", "-n", f"{host}.local"], timeout=3).split()
    return [ipaddress.ip_address(a) for a in out[1:2]]


def parse_ports(spec):
    """"80,8000-8010" -> [80, 8000, ..., 8010]"""
    ports = set()
    try:
        for part in spec.split(","):
            lo, _, hi = part.strip().partition("-")
            ports.update(range(int(lo), int(hi or lo) + 1))
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid port list: {spec!r}")
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise argparse.ArgumentTypeError(f"ports must be 1-65535: {spec!r}")
    return sorted(ports)


def tcp_open(addr, port, timeout):
    try:
        with socket.create_connection((str(addr), port), timeout=timeout):
            return True
    except OSError:
        return False


def reverse_dns(addr):
    out = run(["getent", "hosts", addr], timeout=3).split()
    if len(out) >= 2 and out[1] != addr:
        return clean_host(out[1])
    return None


def clean_host(name):
    if not name:
        return None
    name = name.rstrip(".")
    if name.endswith(".local"):
        name = name[: -len(".local")]
    return None if GENERIC_HOST_RE.match(name) or name == "_gateway" else name


def is_lan_name(name):
    return "." not in name or name.endswith(LAN_SUFFIXES)


def clean_service_name(name):
    name = re.sub(r"\s*\[[0-9a-f:]{17}\]$", "", name, flags=re.I)  # "host [mac]" workstation records
    name = re.sub(r"-[0-9a-f]{32}$", "", name, flags=re.I)  # "Google-Home-Mini-<id>"
    return name or None


# --- vendor lookup ---------------------------------------------------------

def load_oui():
    table = {}
    for path, digits in OUI_FILES:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for row in csv.reader(fh):
                    if len(row) >= 3 and len(row[1]) == digits:
                        table.setdefault(row[1].upper(), row[2].strip())
        except OSError:
            continue
    return table


def vendor(mac, oui):
    if not mac:
        return ""
    hexmac = mac.replace(":", "").upper()
    for n in (9, 7, 6):
        if hexmac[:n] in oui:
            return oui[hexmac[:n]]
    if int(hexmac[1], 16) & 0x2:
        return "(random MAC)"
    return "?"


# --- main ------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-i", "--interface", help="interface to scan (default: default-route NIC)")
    ap.add_argument("-w", "--wait", type=float, default=3.0, help="seconds to wait for ARP/NDP replies")
    ap.add_argument("-p", "--ports", type=parse_ports, help="TCP ports to probe, e.g. 80,8080 or 8000-8010")
    ap.add_argument("-t", "--port-timeout", type=float, default=1.0, help="seconds per TCP connect (default 1)")
    args = ap.parse_args()

    dev = args.interface or default_interface()
    my_mac = open(f"/sys/class/net/{dev}/address").read().strip().lower()
    my_v4, my_v6 = interface_addresses(dev)
    print(f"Interface: {dev} ({my_mac})" + ("" if is_physical(dev) else " [not physical]"), file=sys.stderr)

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=32)
    browse = pool.submit(avahi_browse, dev)

    for iface in my_v4:
        sweep_ipv4(iface)
    stable_v6 = [i.ip for i, temp in my_v6 if not temp] or [i.ip for i, _ in my_v6]
    ping_all_nodes(dev, stable_v6[:1])

    # Hosts with EUI-64 addresses that ignored the multicast ping still answer NDP.
    neigh = neighbours(dev)
    prefixes = {i.network for i, _ in my_v6 if i.network.prefixlen == 64}
    poke(socket.AF_INET6, (eui64(p, m) for p in prefixes for m in set(neigh.values())), dev)

    mdns = browse.result()
    poke(socket.AF_INET6, (a for a, *_ in mdns if ":" in a and not a.startswith("fe80")), dev)
    time.sleep(args.wait)
    neigh = neighbours(dev)

    # Build devices keyed by MAC.
    devices = {}

    def entry(mac):
        return devices.setdefault(mac, {"v4": set(), "v6": set(), "names": {}})

    for addr, mac in neigh.items():
        ip = ipaddress.ip_address(addr)
        if ip.version == 4:
            entry(mac)["v4"].add(ip)
        elif ip.is_global:
            entry(mac)["v6"].add(ip)
        else:
            entry(mac)  # link-local only: still a device on the LAN
    me = entry(my_mac)
    me["v4"].update(i.ip for i in my_v4)
    me["v6"].update(i.ip for i, _ in my_v6 if i.ip.is_global)
    me["names"]["self"] = socket.gethostname()

    # Name candidates, by source: host (mDNS hostname), rdns, fn (friendly name TXT), svc, model.
    for addr, host, svc, txt in mdns:
        mac = neigh.get(addr)
        if mac is None and addr in {str(i.ip) for i in my_v4} | {str(i.ip) for i, _ in my_v6}:
            mac = my_mac
        if mac is None:
            continue
        names = entry(mac)["names"]
        if clean_host(host):
            names.setdefault("host", clean_host(host))
        if txt.get("fn"):
            names.setdefault("fn", txt["fn"])
        if txt.get("md"):
            names.setdefault("model", txt["md"])
        if clean_service_name(svc):
            names.setdefault("svc", clean_service_name(svc))

    lookups = {}
    for mac, d in devices.items():
        for ip in sorted(d["v4"]) + sorted(d["v6"]):
            # IPv6 PTR records usually come from the ISP and are generic, so rank them last.
            lookups[pool.submit(reverse_dns, str(ip))] = (mac, f"rdns{ip.version}")
            if "host" not in d["names"]:
                lookups[pool.submit(avahi_reverse, str(ip))] = (mac, "host")
    for fut in concurrent.futures.as_completed(lookups):
        mac, kind = lookups[fut]
        name = fut.result()
        name = clean_host(name) if kind == "host" else name
        if kind == "rdns6" and name and not is_lan_name(name):
            name = None  # ISP-assigned PTR like host-xyz.pd.example.net
        if name:
            devices[mac]["names"].setdefault(kind, name)

    # A host with several NICs on the LAN may answer ARP for all its addresses from
    # one NIC ("ARP flux"), leaving the other MAC without IPv4. Fall back to mDNS.
    forward = {mac: pool.submit(avahi_forward4, d["names"]["host"])
               for mac, d in devices.items() if not d["v4"] and "host" in d["names"]}
    for mac, fut in forward.items():
        devices[mac]["v4_mdns"] = set(fut.result())

    # Probe IPv4 addresses; fall back to IPv6 for devices that have no IPv4.
    probes = {}
    for mac, d in (devices.items() if args.ports else ()):
        d["open"] = set()
        for addr in sorted(d["v4"] | d.get("v4_mdns", set())) or sorted(d["v6"]):
            for port in args.ports:
                probes[pool.submit(tcp_open, addr, port, args.port_timeout)] = (mac, port)
    for fut in concurrent.futures.as_completed(probes):
        if fut.result():
            mac, port = probes[fut]
            devices[mac]["open"].add(port)
    pool.shutdown()

    gateways = {r.get("gateway") for r in ip_json("route", "show", "default") + ip_json("-6", "route", "show", "default")}
    gw_macs = {neigh[g] for g in gateways if g in neigh}

    oui = load_oui()
    rows = []
    for mac, d in devices.items():
        n = d["names"]
        name = next((n[k] for k in ("self", "host", "rdns4", "fn", "svc", "model", "rdns6") if k in n), "")
        extra = [n["fn"]] if "fn" in n and n["fn"] != name else []
        if "model" in n and n["model"] != name:
            extra.append(n["model"])
        if extra:
            name += f" ({', '.join(extra)})"
        if mac == my_mac:
            name += " [this host]"
        if mac in gw_macs:
            name += " [gateway]"
        v4_mdns = d.get("v4_mdns", set())
        rows.append((
            min(d["v4"] or v4_mdns, default=None),
            mac,
            name.strip(),
            vendor(mac, oui),
            ", ".join([str(a) for a in sorted(d["v4"])] + [f"{a}*" for a in sorted(v4_mdns)]),
            [str(a) for a in sorted(d["v6"])],
            ", ".join(map(str, sorted(d.get("open", ())))),
        ))
    rows.sort(key=lambda r: (r[0] is None, r[0] or 0, r[1]))
    print_table(rows, show_ports=bool(args.ports))


def print_table(rows, show_ports=False):
    header = ("MAC", "Name", "Vendor", "IPv4", "Public IPv6", "Open ports")
    lines = []
    for _, mac, name, vend, v4, v6, ports in rows:
        v6 = v6 or [""]
        lines.append((mac, name, vend[:32], v4, v6[0], ports))
        lines.extend(("", "", "", "", a, "") for a in v6[1:])
    if not show_ports:
        header = header[:5]
        lines = [l[:5] for l in lines]
    widths = [max(len(header[i]), *(len(l[i]) for l in lines)) for i in range(len(header))]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*header))
    print(fmt.format(*("-" * w for w in widths)))
    for l in lines:
        print(fmt.format(*l).rstrip())
    if any("*" in l[3] for l in lines):
        print("\n* IPv4 from mDNS only: ARP answered for it with another MAC of the same host")
    sys.stdout.flush()
    print(f"\n{len(rows)} devices", file=sys.stderr)


if __name__ == "__main__":
    main()
