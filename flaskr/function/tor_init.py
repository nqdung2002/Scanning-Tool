import subprocess, os, requests, time, socket
from stem import Signal
from stem.control import Controller

# Lấy biến môi trường
raw_host = os.getenv("TOR_CONTROL_HOST")  
raw_port = os.getenv("TOR_CONTROL_PORT")

if raw_host and ':' in raw_host:
    h, p = raw_host.rsplit(':', 1)
    TOR_HOST = h
    TOR_PORT = int(p)
elif raw_host:
    TOR_HOST = raw_host
    TOR_PORT = int(raw_port or 9051)
else:
    TOR_HOST = None
    TOR_PORT = int(raw_port or 9051)

TOR_AUTO_START = os.getenv("TOR_AUTO_START", "1") == "1"
password = os.getenv("TOR_PASSWORD")
_tor_proc = None

def ensure_tor_running():
    global _tor_proc
    if TOR_HOST:                   # chạy trong Docker, đã có service tor
        wait_control_ready(TOR_HOST, TOR_PORT)
        return
    if TOR_AUTO_START:
        _tor_proc = start_tor_local()
        wait_control_ready("127.0.0.1", TOR_PORT)

def start_tor_local():
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

def renew_tor_ip():
    host = TOR_HOST or "127.0.0.1"
    ip = socket.gethostbyname(host)
    with Controller.from_port(address=ip, port=TOR_PORT) as controller:
        if password:
            controller.authenticate(password=password)
        else:
            controller.authenticate()
        controller.signal(Signal.NEWNYM)
        print("Đã khởi tạo lại IP của Tor")
        
    SOCKS = os.getenv("SOCKS_PROXY", "socks5h://127.0.0.1:9050")
    proxies = {'http': SOCKS, 'https': SOCKS}

    try:
        response = requests.get('https://api.ipify.org', proxies=proxies, timeout=20)
        print(f"IP mới của Tor: {response.text}")
    except Exception as e:
        print(f"Lỗi khi lấy IP mới: {e}")

def wait_control_ready(host, port, timeout=30):
    start = time.time()
    while time.time() - start < timeout:
        with socket.socket() as s:
            if s.connect_ex((host, port)) == 0:
                return True
        time.sleep(1)
    raise RuntimeError("Tor ControlPort không sẵn sàng trong 30s")

def stop_tor():
    if _tor_proc:
        _tor_proc.terminate()


# Test
# while True:
#     renew_tor_ip()
#     print(requests.get('https://api.ipify.org', proxies=proxies).text)
#     time.sleep(10)