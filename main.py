import os
import sys
import time
import argparse
import threading
import subprocess
from attacks import *
from scapy.all import *
from scapy.layers.dot11 import *

ATTACKS = [
    ("PIN Brute", "Perform a brute force attack on the WiFi Pin for unauthorized access."),
    ("Check Admin Status",   "Identify if the Admin is actively logged in and editing the configuration settings."),
    ("Admin Login Brute Force", "Bypass auth rate limiting by brute forcing authorization cookies."),
    ("Command Injection", "Run arbitrary commands as the Admin user. This requires Admin access (Refer to Attack #3)"),
    ("Denial of Service (DoS)",   "Utilize a Stack Overflow to take down the Admin console (Requires physical restart to fix)"),
    ("Light Show", "Start a light show from the router"),
]

URL = ""
PASSWORD = ""
IP = ""
def check_admin() -> None:
    if os.getuid() != 0:
        sys.exit("[ERROR] Mocking Bird must be run as root")

def get_default_iface() -> str:
    iface = conf.iface
    return iface if iface else ""

def extract_channel(packet) -> int | None:
    elt = packet[Dot11Elt] if Dot11Elt in packet else None
    while elt:
        if elt.ID == 3 and elt.len == 1:
            return int.from_bytes(elt.info, "big")
        elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
    return None

def extract_ssid(packet) -> str:
    elt = packet[Dot11Elt] if Dot11Elt in packet else None
    while elt:
        if elt.ID == 0:
            try:
                return elt.info.decode("utf-8", errors="replace")
            except Exception:
                return "<decode error>"
        elt = elt.payload if isinstance(elt.payload, Dot11Elt) else None
    return "<hidden>"

def extract_signal(packet) -> int | None:
    if RadioTap in packet:
        try:
            return packet[RadioTap].dBm_AntSignal
        except AttributeError:
            pass
    return None

def parse_beacon(packet) -> dict | None:
    if not (Dot11Beacon in packet and Dot11 in packet):
        return None
    bssid = packet[Dot11].addr3
    if not bssid:
        return None
    return {
        "BSSID":   bssid.lower(),
        "SSID":    extract_ssid(packet),
        "Channel": extract_channel(packet),
        "Signal":  extract_signal(packet),
    }

def print_header() -> None:
    print("\n" + "═" * 83)
    print(f"  {'#':<4} {'SSID':<32} {'BSSID':<19} {'CH':>3}  {'SIGNAL':<10}")
    print("═" * 83)

def fmt_signal(dbm: int | None) -> str:
    if dbm is None:
        return "  n/a"
    return f"{dbm:>4} dBm"

def display_network(net: dict) -> None:
    num = net.get("Number", "?")
    ssid = net.get("SSID", "")[:32]
    bssid = net.get("BSSID", "??:??:??:??:??:??")
    channel = str(net.get("Channel", "?"))
    signal = fmt_signal(net.get("Signal"))
    print(f"{num:<4} {ssid:<32} {bssid:<19} {channel:>3} {signal}")

def select_target_menu(networks: dict) -> dict | None:
    if not networks:
        print("[ERROR] No networks available to target.")
        return None

    print("\n" + "=" * 83)
    print("Mocking Bird — Select Your Target")
    print("=" * 83)
    print_header()
    for net in sorted(networks.values(), key=lambda n: n["Number"]):
        display_network(net)
    print("=" * 83)

    try:
        selection = int(input("\nEnter network # to target (0 to cancel): ").strip())
        if selection == 0:
            return None
        target = next((n for n in networks.values() if n.get("Number") == selection), None)
        if target:
            return target
    except ValueError:
        pass
        
    print("Selection invalid or cancelled.")
    return None

def attack_menu_direct(target: dict) -> tuple | None:
    print(f"\nTarget: {target['SSID']}  ({target['BSSID']})")
    print("=" * 83)
    print("Mocking Bird — Attack Menu")
    print("=" * 83)
    for i, (name, desc) in enumerate(ATTACKS, 1):
        print(f"\n  [{i}] {name}")
        print(f"      {desc}")
    print("=" * 83)

    try:
        attack_choice = int(input("Select attack (0 to cancel): ").strip())
    except (ValueError, EOFError):
        return None

    if attack_choice == 0:
        return None

    if 1 <= attack_choice <= len(ATTACKS):
        name, _ = ATTACKS[attack_choice - 1]
        print(f"[SELECTED] {name} against {target['SSID']}")
        return target, attack_choice

    print(f"No attack #{attack_choice}")
    return None

class Scanner:
    def __init__(self, iface: str) -> None:
        self.iface = iface
        self.networks: dict[str, dict] = {}
        self._counter = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.output_paused = False

    def ingest(self, net: dict) -> None:
        bssid = net.get("BSSID", "")
        if not bssid:
            return
        with self._lock:
            if bssid in self.networks:
                self.networks[bssid].update(
                    {k: v for k, v in net.items() if v is not None}
                )
                return
            self._counter += 1
            net["Number"] = self._counter
            self.networks[bssid] = net

        if not self.output_paused:
            if self._counter == 1:
                print_header()
            display_network(net)
            ts = time.strftime("%H:%M:%S")
            print(f"\n  [{ts}]  Networks seen: {self._counter}\n")

    def handle_packet(self, packet) -> None:
        net = parse_beacon(packet)
        if net:
            self.ingest(net)

    def hop_channels(self):
        channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
        while not self._stop.is_set():
            for ch in channels:
                if self._stop.is_set():
                    break
                try:
                    subprocess.run(["iw", "dev", self.iface, "set", "channel", str(ch)], 
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception:
                    pass
                time.sleep(0.5)

    def run_scapy_sniff(self) -> None:
        try:
            sniff(
                iface=self.iface,
                prn=self.handle_packet,
                store=False,
                stop_filter=lambda _: self._stop.is_set(),
            )
        except Exception:
            pass

    def run_initial_nmcli_scan(self) -> None:
        print("[*] Running initial local network scan.")
        try:
            result = subprocess.run(
                ["nmcli", "-t", "-f", "BSSID,SSID,CHAN,SIGNAL", "dev", "wifi"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.strip().split("\n"):
                    if not line:
                        continue
                    parts = line.split(":")
                    if len(parts) < 4:
                        continue
                    
                    bssid_clean = ":".join(parts[0:6]).replace("\\", "").strip().lower()
                    ssid_clean = parts[6].strip()
                    chan_clean = parts[7].strip()
                    sig_clean = parts[8].strip()

                    if not ssid_clean or ssid_clean == "--":
                        ssid_clean = "<hidden>"

                    normalized_net = {
                        "BSSID": bssid_clean,
                        "SSID": ssid_clean,
                        "Channel": int(chan_clean) if chan_clean.isdigit() else "n/a",
                        "Signal": int(sig_clean) if sig_clean.replace("-","").isdigit() else None
                    }
                    self.ingest(normalized_net)
        except Exception as e:
            print(f"[!] nmcli startup poll skipped/failed: {e}")

    def start(self) -> None:
        self.run_initial_nmcli_scan()

        print("[*] Conintuing to listen for additional networks...")
        threading.Thread(target=self.hop_channels, daemon=True).start()
        threading.Thread(target=self.run_scapy_sniff, daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    def snapshot(self) -> dict:
        with self._lock:
            return dict(self.networks)

def start_key_listener(callback_map: dict) -> None:
    def listen_posix():
        import tty, termios, os, signal
        fd  = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while True:
                ch = sys.stdin.read(1)
                
                if ch == '\x03':  # Ctrl+C
                    termios.tcsetattr(fd, termios.TCSADRAIN, old)
                    os.kill(os.getpid(), signal.SIGINT)
                    break
                
                fn = callback_map.get(ch.lower())
                if fn:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old)
                    fn()
                    tty.setraw(fd)
        except Exception:
            pass
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

    threading.Thread(target=listen_posix, daemon=True).start()

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mocking Bird — WiFi Exploitation Framework")
    parser.add_argument("-i", "--iface", default="", help="Wireless interface",)
    return parser.parse_args()

def main() -> None:
    check_admin()
    args  = parse_args()
    iface = args.iface or get_default_iface()

    if not iface:
        sys.exit("[ERROR] Could not determine a wireless interface.")

    print("\n" + "═" * 83)
    print("  Mocking Bird — WiFi Exploitation Framework")
    print(f"  Interface:  Scapy Intercept [{iface}]")
    print("  T — Open Target Select Menu  |  Ctrl+C — quit")
    print("═" * 83 + "\n")

    scanner = Scanner(iface)
    scanner.start()
    
    def handle_target_selection():
        global URL
        global IP
        global PASSWORD
        scanner.output_paused = True 
        target = select_target_menu(scanner.snapshot())
        if target:
            result = attack_menu_direct(target)
            if result:
                target, attack = result
                match attack:
                    case 1:
                        ssid_brute(target["SSID"])
                    case 2:
                        if not URL:
                            URL = "http://" +str(input("[!] Enter URL (IP) for the Admin console:").strip()) + "/"
                        query_admin_status(URL)
                    case 3:
                        password_list = "rockyou.txt"
                        if not URL:
                            URL = "http://" +str(input("[!] Enter URL (IP) for the Admin console:").strip()) + "/"
                        PASSWORD = brute_force_login(URL, password_list)
                    case 4:
                        print("Dhruv Kandula")
                    case 5:
                        if not IP:
                            IP = str(input("[!] Enter IP of the TP-Link Router:").strip())
                        dos_admin_portal(IP)
                    case 6:
                        if not URL:
                            URL = "http://" +str(input("[!] Enter URL (IP) for the Admin console:").strip()) + "/"
                        if PASSWORD:
                            print(f"[-] Please get the Admin password before running this attack")
                            lightshow(URL, PASSWORD)
                        else:
                            password = str(input("[!] Enter the Admin password:").strip())
                            lightshow(URL, password)
        
        print("\n[*] Returning to monitoring view...")
        scanner.output_paused = False

    start_key_listener({"t": handle_target_selection})

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n  [*] Stopping — goodbye.\n")
        scanner.stop()
        sys.exit(0)

if __name__ == "__main__":
    main()