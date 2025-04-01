import subprocess, os
import time
import requests

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
