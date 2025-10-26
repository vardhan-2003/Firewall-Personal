#!/usr/bin/env python3
import subprocess, logging
logger = logging.getLogger("iptables_enforce")

def add_block(src_ip):
    try:
        subprocess.check_call(["iptables", "-I", "INPUT", "1", "-s", src_ip, "-j", "DROP"])
        subprocess.check_call(["iptables", "-I", "OUTPUT", "1", "-d", src_ip, "-j", "DROP"])
        return True
    except Exception as e:
        logger.error(e)
        return False

def remove_block(src_ip):
    # naive removal: delete all DROP rules matching ip
    try:
        subprocess.check_call(["iptables", "-D", "INPUT", "-s", src_ip, "-j", "DROP"])
    except Exception:
        pass
    try:
        subprocess.check_call(["iptables", "-D", "OUTPUT", "-d", src_ip, "-j", "DROP"])
    except Exception:
        pass
