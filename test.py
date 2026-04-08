#!/usr/bin/env python3
import argparse
import time
from collections import defaultdict, deque

from scapy.all import sniff, ARP, conf

LOG_FILE = "arp_monitor.log"


def now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def log(msg, level="INFO"):
    # afișează tot pe ecran
    print(msg)

    # salvează doar ALERT / CRITICAL / WARN în fișier
    if level in ["ALERT", "CRITICAL", "WARN"]:
        with open(LOG_FILE, "a") as f:
            f.write(msg + "\n")


class ARPWatch:
    def __init__(
        self,
        window_seconds=10,
        burst_threshold=25,
        state_ttl=3600,
        allowlist=None,
        trusted_hosts=None,
    ):
        self.ip_to_mac = {}
        self.mac_to_ips = defaultdict(set)
        self.last_seen = {}
        self.state_ttl = state_ttl

        self.window_seconds = window_seconds
        self.burst_threshold = burst_threshold
        self.events = defaultdict(lambda: deque())

        self.allowlist = set(m.lower() for m in (allowlist or []))
        self.trusted_hosts = {
            ip: mac.lower() for ip, mac in (trusted_hosts or {}).items()
        }

    def _gc(self):
        t = time.time()
        stale_ips = [ip for ip, ts in self.last_seen.items() if (t - ts) > self.state_ttl]

        for ip in stale_ips:
            mac = self.ip_to_mac.get(ip)
            if mac:
                self.mac_to_ips[mac].discard(ip)
                if not self.mac_to_ips[mac]:
                    del self.mac_to_ips[mac]

            self.ip_to_mac.pop(ip, None)
            self.last_seen.pop(ip, None)

    def _rate_check(self, mac):
        t = time.time()
        q = self.events[mac]
        q.append(t)

        while q and (t - q[0]) > self.window_seconds:
            q.popleft()

        if len(q) >= self.burst_threshold and mac not in self.allowlist:
            log(
                f"[{now()}] [ALERT] ARP burst from MAC {mac} -> "
                f"{len(q)} ARP packets in {self.window_seconds}s",
                "ALERT"
            )

    def _check_trusted_host(self, src_ip, src_mac):
        expected_mac = self.trusted_hosts.get(src_ip)
        if not expected_mac:
            return

        if src_mac != expected_mac:
            log(
                f"[{now()}] [CRITICAL] Trusted host MAC mismatch for {src_ip} | "
                f"expected={expected_mac} detected={src_mac}",
                "CRITICAL"
            )
        else:
            log(
                f"[{now()}] [INFO] Trusted host {src_ip} seen with expected MAC {src_mac}",
                "INFO"
            )

    def handle_arp(self, pkt):
        if not pkt.haslayer(ARP):
            return

        a = pkt[ARP]
        op = a.op
        src_ip = a.psrc
        src_mac = (a.hwsrc or "").lower()

        if not src_ip or not src_mac:
            return

        self._gc()
        self._rate_check(src_mac)
        self.last_seen[src_ip] = time.time()

        self._check_trusted_host(src_ip, src_mac)

        prev_mac = self.ip_to_mac.get(src_ip)

        if prev_mac is None:
            self.ip_to_mac[src_ip] = src_mac
            self.mac_to_ips[src_mac].add(src_ip)
            return

        if prev_mac != src_mac:
            if src_ip in self.trusted_hosts:
                log(
                    f"[{now()}] [CRITICAL] IP->MAC changed for trusted host: "
                    f"{src_ip} was {prev_mac}, now {src_mac} (op={op})",
                    "CRITICAL"
                )
            elif src_mac not in self.allowlist:
                log(
                    f"[{now()}] [ALERT] IP->MAC changed: "
                    f"{src_ip} was {prev_mac}, now {src_mac} (op={op})",
                    "ALERT"
                )

            self.mac_to_ips[prev_mac].discard(src_ip)
            self.mac_to_ips[src_mac].add(src_ip)
            self.ip_to_mac[src_ip] = src_mac

        if len(self.mac_to_ips[src_mac]) >= 5 and src_mac not in self.allowlist:
            ips = sorted(self.mac_to_ips[src_mac])
            log(
                f"[{now()}] [WARN] MAC {src_mac} is associated with "
                f"multiple IPs ({len(ips)}): {', '.join(ips)}",
                "WARN"
            )


def main():
    parser = argparse.ArgumentParser(
        description="Detect ARP spoofing / MITM indicators on a LAN."
    )
    parser.add_argument("-i", "--iface", required=True)
    parser.add_argument("--window", type=int, default=10)
    parser.add_argument("--burst", type=int, default=25)
    parser.add_argument("--ttl", type=int, default=3600)
    parser.add_argument("--allow-mac", action="append", default=[])
    parser.add_argument(
        "--trusted-host",
        action="append",
        default=[],
        help="Format: IP=MAC",
    )

    args = parser.parse_args()

    trusted_hosts = {}
    for entry in args.trusted_host:
        if "=" not in entry:
            print(f"[ERROR] Invalid format: {entry}")
            return

        ip, mac = entry.split("=", 1)
        trusted_hosts[ip.strip()] = mac.strip().lower()

    conf.sniff_promisc = True

    watcher = ARPWatch(
        window_seconds=args.window,
        burst_threshold=args.burst,
        state_ttl=args.ttl,
        allowlist=args.allow_mac,
        trusted_hosts=trusted_hosts,
    )

    print(f"[{now()}] Starting ARP MITM watch on {args.iface}")
    print(f"[{now()}] Logging ALERT/CRITICAL/WARN to {LOG_FILE}")
    print(f"[{now()}] Press Ctrl+C to stop\n")

    sniff(iface=args.iface, filter="arp", prn=watcher.handle_arp, store=False)


if __name__ == "__main__":
    main()

    # sudo python3 test.py -i eth0 --trusted-host 192.168.100.10=08:00:27:51:17:a7
    # ssc proiect