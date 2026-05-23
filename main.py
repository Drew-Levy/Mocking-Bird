import subprocess
import sys
import signal
import time
import re
import msvcrt

SCAN_INTERVAL = 10
ssid_list = {}
network_counter = 0


def check_admin():
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[ERROR] Mocking Bird must be run as Administrator to access WiFi interfaces")
        sys.exit(1)


def check_location_services():
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")
        value, _ = winreg.QueryValueEx(key, "Value")
        winreg.CloseKey(key)
        if value.lower() != "allow":
            print("[WARN] Windows Location Services are required for sniffing functionality.")
    except Exception:
        pass


def run_netsh_scan():
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        print("[WARN] netsh scan timed out — retrying next cycle")
        return ""
    except Exception as e:
        print(f"[ERROR] netsh call failed: {e}")
        return ""


def parse_netsh_output(raw):
    networks = []
    current  = {}

    for line in raw.splitlines():
        line = line.strip()

        ssid_match  = re.match(r"^SSID\s+\d+\s*:\s*(.+)$", line)
        bssid_match = re.match(r"^BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})$", line)
        sig_match   = re.match(r"^Signal\s*:\s*(\d+)%$", line)
        chan_match   = re.match(r"^Channel\s*:\s*(\d+)$", line)
        radio_match = re.match(r"^Radio type\s*:\s*(.+)$", line)

        if ssid_match:
            if current.get("SSID") and current.get("BSSID"):
                networks.append(current)
            current = {"SSID": ssid_match.group(1).strip()}
        elif bssid_match:
            if current.get("BSSID"):
                networks.append(dict(current))
                current = {k: v for k, v in current.items()
                           if k not in ("BSSID", "Signal", "Channel", "Radio")}
            current["BSSID"] = bssid_match.group(1).lower()
        elif sig_match:
            current["Signal"] = int(sig_match.group(1))
        elif chan_match:
            current["Channel"] = int(chan_match.group(1))
        elif radio_match:
            current["Radio"] = radio_match.group(1).strip()

    if current.get("SSID") and current.get("BSSID"):
        networks.append(current)

    return networks


def print_header():
    print("\n" + "═" * 83)
    print(f"  {'#':<0} {'SSID':<32} {'BSSID':<19} {'CH':>3}  {'SIGNAL':<6}  RADIO")
    print("═" * 83)


def display_network(net):
    num     = net.get("Number", "?")
    ssid    = net.get("SSID", "")[:32]
    bssid   = net.get("BSSID", "??:??:??:??:??:??")
    channel = str(net.get("Channel","?"))
    sig_pct = net.get("Signal", 0)
    radio   = net.get("Radio", "")

    print(f"{num:<4} {ssid:<32} {bssid:<19} {channel:>3} {sig_pct:>3}%  {radio:>10}")


def attack_menu():
    attacks = [
        ("PIN Brute", "Perform a brute force attack on the WiFi Pin for unauthorized access"),
    ]

    while True:
        print("\n" + "═" * 83)
        print("  Mocking Bird — Attack Menu")
        print("═" * 83)

        for i, (name, desc) in enumerate(attacks, 1):
            print(f"\n [{i}] {name}")
            print(f"{desc}")
        print("\n" + "═" * 83)

        try:
            choice = int(input("  Select an attack (or 0 to exit): ").strip())
        except (ValueError, EOFError):
            print("  Invalid input — enter a number.")
            continue

        if choice == 0:
            print(" Exiting.\n")
            sys.exit(0)
        elif 1 <= choice <= len(attacks):
            name, _ = attacks[choice - 1]
            print(f"\n[SELECTED] {name}")
            print("  (will implement later)\n")
            sys.exit(0)
        else:
            print(f"  No attack numbered {choice}.")


def scan_loop():
    global network_counter

    print("\n" + "═" * 83)
    print("  Mocking Bird — WiFi Explotation Framework")
    print(f"  Scanning every {SCAN_INTERVAL}s   |   Ctrl+C to stop   |   T to select target")
    print("═" * 83)

    while True:
        deadline = time.time() + SCAN_INTERVAL
        while time.time() < deadline:
            if msvcrt.kbhit():
                ch = msvcrt.getch()
                try:
                    if ch.decode("utf-8").lower() == "t":
                        attack_menu()
                except UnicodeDecodeError:
                    pass
            time.sleep(0.1)

        raw = run_netsh_scan()
        networks = parse_netsh_output(raw)

        newly_found = []
        for net in networks:
            key = net.get("BSSID", "")
            if key and key not in ssid_list:
                network_counter += 1
                net["Number"] = network_counter
                ssid_list[key] = net
                newly_found.append(net)

        if newly_found:
            print_header()
            for net in newly_found:
                display_network(net)
            print()
            ts = time.strftime("%H:%M:%S")
            print(f"[{ts}]  Networks found: {len(ssid_list):>3}\n")


if __name__ == "__main__":
    check_admin()
    check_location_services()
    scan_loop()