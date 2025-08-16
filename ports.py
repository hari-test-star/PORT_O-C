import os
import re
import subprocess
import sys
import json
import socket

# --------------------------
# Config
# --------------------------
USAGE_FILE = "fw_usage.json"

# --------------------------
# Helper functions
# --------------------------
def load_usage():
    if os.path.exists(USAGE_FILE):
        with open(USAGE_FILE, "r") as f:
            return json.load(f)
    return {"free_uses": 0, "email_verified": False}

def save_usage(data):
    with open(USAGE_FILE, "w") as f:
        json.dump(data, f)

def show_disclaimer():
    print("="*60)
    print(" DISCLAIMER")
    print("="*60)
    print("This tool is for EDUCATIONAL PURPOSES ONLY.")
    print("You are solely responsible for how you use it.")
    print("The developer assumes NO liability for misuse.")
    print("="*60)
    agree = input("Do you agree to the disclaimer? (yes/no): ").strip().lower()
    if agree != "yes":
        print("[-] You must agree to continue.")
        sys.exit(0)

def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def require_email():
    while True:
        email = input("Enter your email: ").strip()
        if validate_email(email):
            print(f"[+] Email '{email}' accepted.\n")
            return True
        else:
            print("[!] Invalid email format. Try again.")

# --------------------------
# Firewall functions
# --------------------------
def run_cmd(cmd):
    try:
        subprocess.run(cmd, check=True, shell=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {e}")

def block_port(port, proto, direction):
    rules = []
    if proto in ("TCP", "BOTH"):
        if direction in ("in", "both"):
            run_cmd(f'netsh advfirewall firewall add rule name="FWMgr Block TCP IN Port {port}" dir=in action=block protocol=TCP localport={port}')
            rules.append(f"FWMgr Block TCP IN Port {port}")
        if direction in ("out", "both"):
            run_cmd(f'netsh advfirewall firewall add rule name="FWMgr Block TCP OUT Port {port}" dir=out action=block protocol=TCP localport={port}')
            rules.append(f"FWMgr Block TCP OUT Port {port}")
    if proto in ("UDP", "BOTH"):
        if direction in ("in", "both"):
            run_cmd(f'netsh advfirewall firewall add rule name="FWMgr Block UDP IN Port {port}" dir=in action=block protocol=UDP localport={port}')
            rules.append(f"FWMgr Block UDP IN Port {port}")
        if direction in ("out", "both"):
            run_cmd(f'netsh advfirewall firewall add rule name="FWMgr Block UDP OUT Port {port}" dir=out action=block protocol=UDP localport={port}')
            rules.append(f"FWMgr Block UDP OUT Port {port}")
    if rules:
        print("[+] Created block rules:")
        for r in rules:
            print(f"     {r}")

def unblock_port(port, proto, direction):
    rules = []
    if proto in ("TCP", "BOTH"):
        if direction in ("in", "both"):
            run_cmd(f'netsh advfirewall firewall delete rule name="FWMgr Block TCP IN Port {port}" protocol=TCP localport={port} dir=in')
            rules.append(f"FWMgr Block TCP IN Port {port}")
        if direction in ("out", "both"):
            run_cmd(f'netsh advfirewall firewall delete rule name="FWMgr Block TCP OUT Port {port}" protocol=TCP localport={port} dir=out')
            rules.append(f"FWMgr Block TCP OUT Port {port}")
    if proto in ("UDP", "BOTH"):
        if direction in ("in", "both"):
            run_cmd(f'netsh advfirewall firewall delete rule name="FWMgr Block UDP IN Port {port}" protocol=UDP localport={port} dir=in')
            rules.append(f"FWMgr Block UDP IN Port {port}")
        if direction in ("out", "both"):
            run_cmd(f'netsh advfirewall firewall delete rule name="FWMgr Block UDP OUT Port {port}" protocol=UDP localport={port} dir=out')
            rules.append(f"FWMgr Block UDP OUT Port {port}")
    if rules:
        for r in rules:
            print(f"[+] Removed rule: {r}")

def list_rules():
    run_cmd('netsh advfirewall firewall show rule name=all | findstr "FWMgr"')

def clear_rules():
    run_cmd('netsh advfirewall firewall delete rule name=all | findstr "FWMgr"')

def block_all():
    run_cmd('netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound')
    print("[+] ALL connections blocked.")

def allow_all():
    run_cmd('netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound')
    print("[+] ALL connections allowed.")

def export_config():
    run_cmd('netsh advfirewall export "fw_config.wfw"')
    print("[+] Firewall config exported to fw_config.wfw")

def import_config():
    run_cmd('netsh advfirewall import "fw_config.wfw"')
    print("[+] Firewall config imported from fw_config.wfw")

def enable_logging():
    run_cmd('netsh advfirewall set currentprofile logging droppedconnections enable')
    run_cmd('netsh advfirewall set currentprofile logging filename "%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log"')
    print("[+] Logging enabled for dropped connections.")

def show_log():
    logfile = os.path.expandvars(r"%systemroot%\system32\LogFiles\Firewall\pfirewall.log")
    if os.path.exists(logfile):
        with open(logfile, "r") as f:
            lines = f.readlines()[-10:]
            print("".join(lines))
    else:
        print("[!] No log file found.")

def show_ip():
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    print(f"[+] Hostname: {hostname}\n[+] IP Address: {ip}")

# --------------------------
# Main Menu
# --------------------------
def main():
    usage = load_usage()
    show_disclaimer()

    while True:
        print("\n=== WINDOWS FIREWALL MANAGER ===")
        print("1. Block port/port-range")
        print("2. Unblock port/port-range")
        print("3. List tool-created rules")
        print("4. Clear tool-created rules")
        print("5. BLOCK ALL connections (in+out)")
        print("6. ALLOW ALL connections (in+out)")
        print("7. Export firewall config")
        print("8. Import firewall config")
        print("9. Enable firewall logging (dropped connections)")
        print("10. Show recent DROPPED connections from log")
        print("11. Show IP info")
        print("12. Exit")

        choice = input("Enter choice: ").strip()

        if choice == "1" or choice == "2":
            # Check free uses
            if not usage["email_verified"]:
                if usage["free_uses"] >= 3:
                    print("[!] Free usage limit reached. Please verify your email to continue.")
                    if require_email():
                        usage["email_verified"] = True
                        save_usage(usage)
                else:
                    usage["free_uses"] += 1
                    save_usage(usage)

            port = input("Enter port or range (e.g., 80 or 1000-2000): ").strip()
            proto = input("Protocol [TCP/UDP/BOTH]: ").strip().upper()
            direction = input("Direction [in/out/both]: ").strip().lower()

            if choice == "1":
                block_port(port, proto, direction)
            else:
                unblock_port(port, proto, direction)

        elif choice == "3":
            list_rules()
        elif choice == "4":
            clear_rules()
        elif choice == "5":
            block_all()
        elif choice == "6":
            allow_all()
        elif choice == "7":
            export_config()
        elif choice == "8":
            import_config()
        elif choice == "9":
            enable_logging()
        elif choice == "10":
            show_log()
        elif choice == "11":
            show_ip()
        elif choice == "12":
            break
        else:
            print("[!] Invalid choice.")

if __name__ == "__main__":
    main()

