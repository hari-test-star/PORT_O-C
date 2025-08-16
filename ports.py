import subprocess
import socket
import requests
import ctypes
import sys
import re

# ----------- DISCLAIMER -----------
def show_disclaimer():
    print("=" * 60)
    print(" DISCLAIMER")
    print("=" * 60)
    print("This tool is for EDUCATIONAL PURPOSES ONLY.")
    print("You are solely responsible for how you use it.")
    print("The developer assumes NO liability for misuse.")
    print("=" * 60)
    choice = input("Do you agree to the disclaimer? (yes/no): ").strip().lower()
    if choice != "yes":
        print("[!] Exiting. You must agree to the disclaimer.")
        sys.exit()

# ----------- EMAIL CHECK -----------
def validate_email():
    while True:
        email = input("Enter your email: ").strip()
        # Simple regex validation
        if re.match(r"[^@]+@[^@]+\.[^@]+", email):
            print(f"[+] Email '{email}' accepted.")
            return email
        else:
            print("[!] Invalid email format. Try again.")

# ----------- ADMIN CHECK -----------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# ----------- FIREWALL FUNCTIONS -----------

def block_port(port, protocol="TCP", direction="in"):
    """Block a port"""
    try:
        name = f"FWMgr Block {protocol.upper()} {direction.upper()} Port {port}"
        subprocess.run(f'netsh advfirewall firewall delete rule name="{name}"',
                       shell=True, stdout=subprocess.DEVNULL)
        subprocess.run(
            f'netsh advfirewall firewall add rule name="{name}" dir={direction} action=block protocol={protocol} localport={port}',
            shell=True
        )
        print(f"[+] Block rule created: {name}")
    except Exception as e:
        print(f"[!] Error: {e}")

def unblock_port(port, protocol="TCP", direction="in"):
    """Unblock a port"""
    try:
        name = f"FWMgr Block {protocol.upper()} {direction.upper()} Port {port}"
        subprocess.run(f'netsh advfirewall firewall delete rule name="{name}"',
                       shell=True)
        print(f"[+] Removed rule: {name}")
    except Exception as e:
        print(f"[!] Error: {e}")

def block_all():
    try:
        subprocess.run('netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound', shell=True)
        print("[+] All connections blocked.")
    except Exception as e:
        print(f"[!] Error: {e}")

def allow_all():
    try:
        subprocess.run('netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound', shell=True)
        print("[+] All connections allowed.")
    except Exception as e:
        print(f"[!] Error: {e}")

def show_ip_info():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        try:
            public_ip = requests.get("https://api.ipify.org", timeout=5).text
        except requests.RequestException:
            public_ip = "Unable to fetch (No internet)"
        print(f"Local IP : {local_ip}")
        print(f"Public IP: {public_ip}")
    except Exception as e:
        print(f"[!] Error fetching IP info: {e}")

# ----------- MAIN MENU -----------

def main():
    # Disclaimer & email
    show_disclaimer()
    validate_email()

    if not is_admin():
        print("[!] Please run this script as Administrator.")
        sys.exit()

    usage_limit = 10
    actions_done = 0

    while True:
        if actions_done >= usage_limit:
            print(f"[!] Usage limit of {usage_limit} reached. Exiting.")
            break

        print("\n=== WINDOWS FIREWALL MANAGER ===")
        print("1. Block a port")
        print("2. Unblock a port")
        print("3. BLOCK ALL connections (in+out)")
        print("4. ALLOW ALL connections (in+out)")
        print("5. Show IP info")
        print("6. Exit")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            port = input("Enter port: ").strip()
            proto = input("Protocol [TCP/UDP]: ").strip().upper()
            direction = input("Direction [in/out]: ").strip().lower()
            block_port(port, proto, direction)
            actions_done += 1
        elif choice == "2":
            port = input("Enter port: ").strip()
            proto = input("Protocol [TCP/UDP]: ").strip().upper()
            direction = input("Direction [in/out]: ").strip().lower()
            unblock_port(port, proto, direction)
            actions_done += 1
        elif choice == "3":
            block_all()
            actions_done += 1
        elif choice == "4":
            allow_all()
            actions_done += 1
        elif choice == "5":
            show_ip_info()
            actions_done += 1
        elif choice == "6":
            break
        else:
            print("[!] Invalid choice.")

if __name__ == "__main__":
    main()
