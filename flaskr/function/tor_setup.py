import subprocess, os
import time
import requests

TOR_PROXIES = {
    'http': 'socks5h://localhost:9050',
    'https': 'socks5h://localhost:9050'
}

def get_via_tor(url):
    return requests.get(url, proxies=TOR_PROXIES, timeout=30)

def start_tor():
    tor_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../tor/tor/tor.exe'))

    process = subprocess.Popen([
        tor_path,
        "--ControlPort", "9051",
        "--SocksPort", "9050",
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    print("Đang khởi động Tor...")

    for line in process.stdout:
        print(line.strip())
        if "Bootstrapped 100%" in line:
            print("Tor đã khởi động thành công!")
            break

    return process

def stop_tor(process):
    process.terminate()

process = start_tor()
print(get_via_tor('https://api.ipify.org/').text)
print(requests.get('https://api.ipify.org/', timeout=30).text)
stop_tor(process)