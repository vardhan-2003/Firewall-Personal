#!/usr/bin/env python3
"""
Enhanced GUI for Personal Firewall with real-time logs
"""

import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
import threading
import json
import os
import time
from datetime import datetime
from firewall import handle_packet, RULES_FILE, load_rules, INTERFACE  # firewall logic

LOGFILE = "logs/firewall.log"

class FirewallGUI:
    def __init__(self, master):
        self.master = master
        master.title("Personal Firewall")
        master.geometry("900x600")

        # Packet logs area
        self.log_area = scrolledtext.ScrolledText(master, width=100, height=20, state="disabled")
        self.log_area.pack(pady=5)

        # Rule list area
        tk.Label(master, text="Firewall Rules:").pack()
        self.rule_list = scrolledtext.ScrolledText(master, width=100, height=8, state="disabled")
        self.rule_list.pack(pady=5)

        # Buttons
        frame = tk.Frame(master)
        frame.pack(pady=5)

        self.start_btn = tk.Button(frame, text="Start Sniffing", command=self.start_sniff)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = tk.Button(frame, text="Stop Sniffing", command=self.stop_sniff, state="disabled")
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.reload_btn = tk.Button(frame, text="Reload Rules", command=self.reload_rules)
        self.reload_btn.pack(side=tk.LEFT, padx=5)

        self.add_btn = tk.Button(frame, text="Add Rule", command=self.add_rule)
        self.add_btn.pack(side=tk.LEFT, padx=5)

        self.edit_btn = tk.Button(frame, text="Edit Rule", command=self.edit_rule)
        self.edit_btn.pack(side=tk.LEFT, padx=5)

        self.del_btn = tk.Button(frame, text="Delete Rule", command=self.delete_rule)
        self.del_btn.pack(side=tk.LEFT, padx=5)

        # Thread control
        self.sniffing = False
        self.thread = None

        # Load GUI content
        self.update_rule_list()
        self.update_log_area()

    # --- Logs ---
    def log(self, text):
        self.log_area.configure(state="normal")
        self.log_area.insert(tk.END, f"{text}\n")
        self.log_area.yview(tk.END)
        self.log_area.configure(state="disabled")

    def update_log_area(self):
        if os.path.exists(LOGFILE):
            with open(LOGFILE, "r") as f:
                content = f.read()
            self.log_area.configure(state="normal")
            self.log_area.delete(1.0, tk.END)
            self.log_area.insert(tk.END, content)
            self.log_area.yview(tk.END)
            self.log_area.configure(state="disabled")
        self.master.after(2000, self.update_log_area)

    # --- Rules display ---
    def update_rule_list(self):
        global RULES
        RULES = load_rules()
        self.rule_list.configure(state="normal")
        self.rule_list.delete(1.0, tk.END)
        for idx, r in enumerate(RULES, 1):
            self.rule_list.insert(tk.END, f"{idx}. {r}\n")
        self.rule_list.configure(state="disabled")

    # --- Sniffing ---
    def start_sniff(self):
        if self.sniffing:
            return
        self.sniffing = True
        self.thread = threading.Thread(target=self.sniff_loop, daemon=True)
        self.thread.start()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.log("[INFO] Sniffing started...")

    def stop_sniff(self):
        self.sniffing = False
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.log("[INFO] Sniffing stopped.")

    def sniff_loop(self):
        import scapy.all as scapy
        while self.sniffing:
            try:
                # sniff 1 packet at a time on correct interface
                scapy.sniff(count=1, timeout=1, prn=self.handle_packet_gui, store=False, iface=INTERFACE)
            except Exception as e:
                self.log(f"[ERROR] {e}")

    # --- Safe packet handler for GUI logging ---
    def handle_packet_gui(self, pkt):
        try:
            # Call original firewall handler
            handle_packet(pkt)
            # Update GUI log after handling
            self.master.after(0, self.update_log_area)
        except Exception as e:
            self.log(f"[ERROR] handle_packet: {e}")

    # --- Rules management ---
    def reload_rules(self):
        try:
            global RULES
            RULES = load_rules()
            self.log(f"[INFO] Rules reloaded ({len(RULES)} rules).")
            self.update_rule_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to reload rules: {e}")

    def save_rules(self):
        try:
            global RULES
            with open(RULES_FILE, "w") as f:
                json.dump(RULES, f, indent=2)
            self.update_rule_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save rules: {e}")

    def add_rule(self):
        global RULES
        new_rule = {}
        new_rule["id"] = simpledialog.askstring("Rule ID", "Enter unique rule ID:")
        new_rule["action"] = simpledialog.askstring("Action", "allow, block, log:", initialvalue="log")
        new_rule["direction"] = simpledialog.askstring("Direction", "in, out, any:", initialvalue="any")
        new_rule["protocol"] = simpledialog.askstring("Protocol", "tcp, udp, icmp, any:", initialvalue="any")
        new_rule["src_ip"] = simpledialog.askstring("Source IP", "Enter src IP or 'any':", initialvalue="any")
        new_rule["dst_ip"] = simpledialog.askstring("Destination IP", "Enter dst IP or 'any':", initialvalue="any")
        new_rule["src_port"] = simpledialog.askstring("Source Port", "Enter src port or 'any':", initialvalue="any")
        new_rule["dst_port"] = simpledialog.askstring("Destination Port", "Enter dst port or 'any':", initialvalue="any")
        RULES.append(new_rule)
        self.save_rules()
        self.log(f"[INFO] Added new rule: {new_rule['id']}")

    def edit_rule(self):
        global RULES
        idx = simpledialog.askinteger("Edit Rule", "Enter rule number to edit:")
        if not idx or idx < 1 or idx > len(RULES):
            messagebox.showwarning("Invalid", "Invalid rule number")
            return
        r = RULES[idx - 1]
        for key in ["action", "direction", "protocol", "src_ip", "dst_ip", "src_port", "dst_port"]:
            val = simpledialog.askstring(f"{key}", f"Enter new value for {key} (current: {r[key]}):", initialvalue=r[key])
            if val:
                r[key] = val
        self.save_rules()
        self.log(f"[INFO] Edited rule {r['id']}")

    def delete_rule(self):
        global RULES
        idx = simpledialog.askinteger("Delete Rule", "Enter rule number to delete:")
        if not idx or idx < 1 or idx > len(RULES):
            messagebox.showwarning("Invalid", "Invalid rule number")
            return
        r = RULES.pop(idx - 1)
        self.save_rules()
        self.log(f"[INFO] Deleted rule {r['id']}")

# --- Main ---
if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)
    root = tk.Tk()
    app = FirewallGUI(root)
    root.mainloop()
