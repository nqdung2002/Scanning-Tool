import subprocess, os
import time
import requests
from stem import Signal
from stem.control import Controller

def start_tor():
    tor_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../tor/tor/tor.exe'))

    process = subprocess.Popen([
        tor_path,
        "--ControlPort", "9051",
        "--CookieAuthentication", "1",
        "--SocksPort", "9050",
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    print("Đang khởi động Tor...")

    for line in process.stdout:
        if "Bootstrapped 100%" in line:
            print("Tor đã khởi động thành công!")
            break

    return process

def stop_tor(process):
    process.terminate()

def renew_tor_ip():
    with Controller.from_port(address="127.0.0.1", port=9051) as controller:
        controller.authenticate()
        controller.signal(Signal.NEWNYM)
        print("Đã khởi tạo lại IP của Tor")
        
    proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
    }
    try:
        response = requests.get('https://api.ipify.org', proxies=proxies, timeout=10)
        print(f"IP mới của Tor: {response.text}")
    except Exception as e:
        print(f"Lỗi khi lấy IP mới: {e}")

# Test
# while True:
#     renew_tor_ip()
#     print(requests.get('https://api.ipify.org', proxies=proxies).text)
#     time.sleep(10)