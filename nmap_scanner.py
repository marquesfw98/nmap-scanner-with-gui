# ---------------------------------------------------------------
# Project: Nmap Network Scanner
# Author: Marques Robinson
# Date: March 3rd 2025
# Description: port scanner with a GUI using nmap and tkinter
# ---------------------------------------------------------------

import tkinter as tk
from tkinter import messagebox, scrolledtext
import nmap

def run_scan():
    target = target_entry.get()
    ports = ports_entry.get()

    if not target:
        messagebox.showerror("Input Error", "Please enter a target IP or hostname.")
        return

    scanner_output.delete(1.0, tk.END)

    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, ports=ports)
        for host in nm.all_hosts():
            scanner_output.insert(tk.END, f"Host: {host} ({nm[host].hostname()})\n")
            scanner_output.insert(tk.END, f"State: {nm[host].state()}\n")

            for proto in nm[host].all_protocols():
                scanner_output.insert(tk.END, f"\nProtocol: {proto}\n")
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    state = nm[host][proto][port]['state']
                    scanner_output.insert(tk.END, f"Port {port}: {state}\n")

    except Exception as e:
        scanner_output.insert(tk.END, f"Error: {str(e)}\n")

# Creates GUI window using tkinter
window = tk.Tk()
window.title("Nmap Network Scanner")
window.geometry("600x500")

# Ask user to enter a target IP or Hostname of their choosing
tk.Label(window, text="Enter the target IP / Hostname:").pack()
target_entry = tk.Entry(window, width=50)
target_entry.pack()

# Ask user to enter a port range of their choosing
tk.Label(window, text="Enter a port range (e.g., 1-25):").pack()
ports_entry = tk.Entry(window, width=50)
ports_entry.pack()

# Scan button
tk.Button(window, text="Run Scan", command=run_scan).pack(pady=10)

# Output box
scanner_output = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=70, height=20)
scanner_output.pack(padx=10, pady=10)

window.mainloop()
