#!/usr/bin/env python3
"""
firewall.py - Lightweight personal firewall using Scapy
Run as Administrator (Windows) or sudo (Linux):
    python firewall.py
"""

import json
import logging
from logging.handlers import RotatingFileHandler
import os
import subprocess
import threading
import time
from datetime import datetime
from ipaddress import ip_network, ip_address

from scapy.all import sniff, IP, TCP, UDP, ICMP
import netifaces
import psutil

# --- Config ---
RULES_FILE = "rules.json"
LOGFILE = "logs/firewall.log"
INTERFACE = None  # e.g., "Wi-Fi" (Windows) or "eth0" (Linux). None = auto

# --- Logging setup ---
os.makedirs("logs", exist_ok=True)
logger = logging.getLogger("PersonalFirewall")
logger.setLevel(logging.INFO)

fh = RotatingFileHandler(LOGFILE, maxBytes=5 * 1024 * 1024, backupCount=3)
fmt = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
fh.setFormatter(fmt)
logger.addHandler(fh)
logger.addHandler(logging.StreamHandler())  # print to console

# --- Utility: get local IPs ---
def get_local_ipv4_addresses():
    addrs = set()
    for ifname in netifaces.interfaces():
        try:
            fams = netifaces.ifaddresses(ifname)
            if netifaces.AF_INET in fams:
                for entry in fams[netifaces.AF_INET]:
                    addr = entry.get("addr")
                    if addr:
                        addrs.add(addr)
        except Exception:
            continue
    try:
        for nic, addrs_list in psutil.net_if_addrs().items():
            for a in addrs_list:
                if a.family == 2:  # AF_INET
                    addrs.add(a.address)
    except Exception:
        pass
    return addrs


LOCAL_IPS = get_local_ipv4_addresses()

# --- Load and parse rules ---
def load_rules():
    if not os.path.exists(RULES_FILE):
        logger.warning(f"Rules file {RULES_FILE} not found. Creating default empty rules.")
        with open(RULES_FILE, "w") as f:
            json.dump([], f, indent=2)
        return []
    with open(RULES_FILE, "r") as f:
        rules = json.load(f)

    for r in rules:
        r.setdefault("action", "log")
        r.setdefault("direction", "any")
        r.setdefault("protocol", "any")
        r.setdefault("src_ip", "any")
        r.setdefault("dst_ip", "any")
        r.setdefault("src_port", "any")
        r.setdefault("dst_port", "any")
    return rules


RULES = load_rules()
RULES_MTIME = os.path.getmtime(RULES_FILE) if os.path.exists(RULES_FILE) else 0

# --- Match helpers ---
def ip_matches(rule_ip, pkt_ip):
    if rule_ip == "any":
        return True
    try:
        if "/" in str(rule_ip):
            net = ip_network(rule_ip, strict=False)
            return ip_address(pkt_ip) in net
        else:
            return ip_address(pkt_ip) == ip_address(rule_ip)
    except Exception:
        return False


def port_matches(rule_port, pkt_port):
    if rule_port == "any":
        return True
    try:
        return int(rule_port) == int(pkt_port)
    except Exception:
        return False


def proto_matches(rule_proto, pkt):
    if rule_proto == "any":
        return True
    proto = rule_proto.lower()
    if proto == "tcp":
        return pkt.haslayer(TCP)
    if proto == "udp":
        return pkt.haslayer(UDP)
    if proto == "icmp":
        return pkt.haslayer(ICMP)
    return False


def packet_direction(pkt):
    """If src is local -> outbound, if dst is local -> inbound."""
    try:
        if not pkt.haslayer(IP):
            return "any"
        s = pkt[IP].src
        d = pkt[IP].dst
        if s in LOCAL_IPS and d not in LOCAL_IPS:
            return "out"
        if d in LOCAL_IPS and s not in LOCAL_IPS:
            return "in"
    except Exception:
        pass
    return "any"


def match_rule(rule, pkt):
    if not pkt.haslayer(IP):
        return False
    src = pkt[IP].src
    dst = pkt[IP].dst

    if not proto_matches(rule["protocol"], pkt):
        return False

    rdir = rule.get("direction", "any")
    pdir = packet_direction(pkt)
    if rdir != "any" and rdir != pdir and pdir != "any":
        return False

    if not ip_matches(rule["src_ip"], src):
        return False
    if not ip_matches(rule["dst_ip"], dst):
        return False

    sport = dport = None
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

    if rule["src_port"] != "any" and sport is None:
        return False
    if rule["dst_port"] != "any" and dport is None:
        return False
    if sport is not None and not port_matches(rule["src_port"], sport):
        return False
    if dport is not None and not port_matches(rule["dst_port"], dport):
        return False
    return True


# --- Optional system-level enforcement (Linux only) ---
def iptables_block_ip(ip, reason="blocked-by-personal-firewall"):
    try:
        subprocess.check_call(["iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"])
        subprocess.check_call(["iptables", "-I", "OUTPUT", "1", "-d", ip, "-j", "DROP"])
        logger.info(f"iptables: blocked ip {ip} ({reason})")
    except Exception as e:
        logger.error(f"Failed to add iptables rule for {ip}: {e}")


# --- Logging and actions ---
def log_packet(pkt, rule=None):
    ts = datetime.utcnow().isoformat() + "Z"
    summary = {
        "time": ts,
        "src": pkt[IP].src if pkt.haslayer(IP) else "NA",
        "dst": pkt[IP].dst if pkt.haslayer(IP) else "NA",
        "protocol": pkt[IP].proto if pkt.haslayer(IP) else "NA",
        "rule": rule.get("id") if rule else None,
        "action": rule.get("action") if rule else None,
    }
    logger.info("PACKET %s", json.dumps(summary))


def handle_packet(pkt):
    global RULES
    matched = False
    for r in RULES:
        try:
            if match_rule(r, pkt):
                matched = True
                log_packet(pkt, rule=r)
                if r.get("action") == "block":
                    src_ip = pkt[IP].src
                    # On Linux, enforce via iptables; on Windows, just log
                    if os.name != "nt":
                        iptables_block_ip(src_ip, reason=f"rule-{r.get('id')}")
                break
        except Exception as e:
            logger.exception("Error matching rule: %s", e)
    if not matched:
        pass


# --- Watch for rule updates ---
def rules_watcher_thread(interval=5):
    global RULES, RULES_MTIME
    while True:
        try:
            if os.path.exists(RULES_FILE):
                m = os.path.getmtime(RULES_FILE)
                if m != RULES_MTIME:
                    logger.info("Detected rules file change. Reloading...")
                    RULES = load_rules()
                    RULES_MTIME = m
        except Exception:
            logger.exception("rules watcher error")
        time.sleep(interval)


# --- Start sniffing ---
def start_sniff():
    logger.info("Local IPs: %s", LOCAL_IPS)
    logger.info("Loaded %d rules", len(RULES))
    logger.info("Starting packet sniffing... (CTRL+C to stop)")
    sniff(prn=handle_packet, store=False, iface=INTERFACE)


if __name__ == "__main__":
    t = threading.Thread(target=rules_watcher_thread, daemon=True)
    t.start()
    try:
        start_sniff()
    except KeyboardInterrupt:
        logger.info("Stopped by user")
