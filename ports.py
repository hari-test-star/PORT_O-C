import subprocess
import socket
import requests
import ctypes
import sys
import re

# ----------- ADMIN CHECK -----------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# ----------- FIREWALL FUNCTIONS -----------
def block_port(port, proto="TCP", direction="in"):
    try:
        rule_name = f"FWMgr Block {proto.upper()} {direction.upper()} Port {port}"
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name}"', shell=True, stdout=subprocess.DEVNULL)
        subprocess.run(f'netsh advfirewall firewall add rule name="{rule_name}" dir={direction} action=block protocol={proto} localport={port}', shell=True)
        print(f"[+] Port {port} blocked successfully ({proto}/{direction}).")
    except Exception as e:
        print(f"[!] Error blocking port {port}: {e}")

def unblock_port(port, proto="TCP", direction="in"):
    try:
        rule_name = f"FWMgr Block {proto.upper()} {direction.upper()} Port {port}"
        subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name}"', shell=True)
        print(f"[+] Port {port} unblocked successfully ({proto}/{direction}).")
    except Exception as e:
        print(f"[!] Error unblocking port {port}: {e}")

def clear_all_rules():
    try:
        subprocess.run('netsh advfirewall firewall delete rule name=all', shell=True)
        print("[+] All firewall rules cleared successfully.")
    except Exception as e:
        print(f"[!] Error clearing firewall rules: {e}")

def block_all_ports():
    try:
        subprocess.run('netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound', shell=True)
        print("[+] All ports blocked (inbound+outbound).")
    except Exception as e:
        print(f"[!] Error blocking all ports: {e}")

def unblock_all_ports():
    try:
        subprocess.run('netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound', shell=True)
        print("[+] All ports unblocked (inbound+outbound).")
    except Exception as e:
        print(f"[!] Error unblocking all ports: {e}")

def export_config(filename="firewall_config.wfw"):
    try:
        subprocess.run(f'netsh advfirewall export "{filename}"', shell=True)
        print(f"[+] Firewall config exported to {filename}")
    except Exception as e:
        print(f"[!] Error exporting config: {e}")

def import_config(filename="firewall_config.wfw"):
    try:
        subprocess.run(f'netsh advfirewall import "{filename}"', shell=True)
        print(f"[+] Firewall config imported from {filename}")
    except Exception as e:
        print(f"[!] Error importing config: {e}")

def enable_logging():
    try:
        subprocess.run('netsh advfirewall set currentprofile logging droppedconnections enable', shell=True)
        subprocess.run('netsh advfirewall set currentprofile logging filename "%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log"', shell=True)
        print("[+] Firewall logging enabled.")
    except Exception as e:
        print(f"[!] Error enabling logging: {e}")

def show_dropped_log():
    try:
        log_path = r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
        with open(log_path, "r") as f:
            lines = f.readlines()[-10:]
        print("\n".join(lines))
    except Exception as e:
        print(f"[!] Error reading log file: {e}")

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

# ----------- DISCLAIMER + EMAIL + LIMIT -----------
def disclaimer_and_email():
    print("="*60)
    print(" DISCLAIMER")
    print("="*60)
    print("This tool is for EDUCATIONAL PURPOSES ONLY.")
    print("You are solely responsible for how you use it.")
    print("The developer assumes NO liability for misuse.")
    print("="*60)

    agree = input("Do you agree to the disclaimer? (yes/no): ").strip().lower()
    if agree != "yes":
        print("Exiting. You must accept the disclaimer to continue.")
        sys.exit()

    email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    while True:
        email = input("Enter your email: ").strip()
        if re.match(email_pattern, email):
            print(f"[+] Email '{email}' accepted.\n")
            break
        else:
            print("[!] Invalid email format. Try again.")

def main():
    if not is_admin():
        print("[!] Please run this script as Administrator.")
        sys.exit()

    disclaimer_and_email()

    # Limit: only 3 block/unblock actions allowed
    action_limit = 3
    action_count = 0

    while True:
        print("\n=== WINDOWS FIREWALL MANAGER ===")
        print("1. Block port")
        print("2. Unblock port")
        print("3. List/Clear all firewall rules")
        print("4. BLOCK ALL connections (in+out)")
        print("5. ALLOW ALL connections (in+out)")
        print("6. Export firewall config")
        print("7. Import firewall config")
        print("8. Enable firewall logging (dropped connections)")
        print("9. Show recent DROPPED connections from log")
        print("10. Show IP info")
        print("11. Exit")

        choice = input("Enter choice: ").strip()

        if choice == "1":
            if action_count >= action_limit:
                print("[!] Block/Unblock limit reached (3). Restart script to continue.")
                continue
            port = input("Enter port: ").strip()
            proto = input("Protocol [TCP/UDP]: ").strip().upper()
            direction = input("Direction [in/out]: ").strip().lower()
            block_port(port, proto, direction)
            action_count += 1

        elif choice == "2":
            if action_count >= action_limit:
                print("[!] Block/Unblock limit reached (3). Restart script to continue.")
                continue
            port = input("Enter port: ").strip()
            proto = input("Protocol [TCP/UDP]: ").strip().upper()
            direction = input("Direction [in/out]: ").strip().lower()
            unblock_port(port, proto, direction)
            action_count += 1

        elif choice == "3":
            clear_all_rules()

        elif choice == "4":
            block_all_ports()

        elif choice == "5":
            unblock_all_ports()

        elif choice == "6":
            export_config()

        elif choice == "7":
            import_config()

        elif choice == "8":
            enable_logging()

        elif choice == "9":
            show_dropped_log()

        elif choice == "10":
            show_ip_info()

        elif choice == "11":
            break

        else:
            print("[!] Invalid choice.")

if __name__ == "__main__":
    main()

