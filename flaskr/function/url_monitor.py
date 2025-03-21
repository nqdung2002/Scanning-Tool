import requests, uuid, logging, os, json
import subprocess
from flaskr import create_app
from datetime import datetime
from flaskr import socketio, db
from flaskr.function.send_email import send_mail
from requests.adapters import HTTPAdapter, Retry

LOG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../log'))

# Log lỗi khi kiểm tra status
logger = logging.getLogger("connection_error")
logger.setLevel(logging.ERROR)
logger.propagate = False
file_handler = logging.FileHandler(os.path.join(LOG_DIR, "connection_error.log"), encoding="utf-8")
file_formatter = logging.Formatter("%(asctime)s - %(message)s")
file_handler.setFormatter(file_formatter)
logger.addHandler(file_handler)

# Tạo session để retry, tránh connection abort
def create_session_with_retries():
    session = requests.Session()
    retries = Retry(
        total=2,              # Số lần thử lại
        backoff_factor=1,     # Tăng dần thời gian chờ giữa các lần retry
        status_forcelist=[429, 500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def check_url_status(url, stop_event, url_id=None, monitoring_active=None, emit_event='url_status_update', app=None):
    if url_id is None:
        temp_id = str(uuid.uuid4())
    else:
        temp_id = url_id

    session = create_session_with_retries()
    err_count = 0
    redirect_count = 0
    max_redirects = 10
    last_status = None

    while not stop_event.is_set():
        try:
            response = session.get(url, timeout=6)
            current_status = response.status_code

            if current_status in [301, 302]:
                new_url = response.headers.get('Location')
                if new_url:
                    url = new_url
                    redirect_count += 1
                    if redirect_count >= max_redirects:
                        print(f"Quá nhiều redirect cho {url}")
                        break
                    continue

            last_status = current_status
            err_count = 0
            if stop_event.is_set():
                break
            socketio.emit(emit_event, {
                'url_id': temp_id,
                'url': url,
                'url_status': current_status,
                'last_success_time': datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
                "monitoring_active": monitoring_active
            })
            print(f"Status của {url}: {current_status}")
        except requests.RequestException as e:
            err_count += 1
            current_status = f"{last_status} (Lỗi {err_count})"
            socketio.emit(emit_event, {
                'url_id': temp_id,
                'url': url,
                'url_status': current_status,
                'last_success_time': None,
                "monitoring_active": monitoring_active
            })
            print(f"Lỗi khi kiểm tra {url}: {e}")
            if err_count >= 2:
                socketio.emit('error', {'message': f"Lỗi khi kiểm tra {url}: {e}"})
                logger.error(f"Lỗi khi kiểm tra {url}: {e}")
                if url_id is not None and app is not None:
                    try:
                        with app.app_context():
                            from flaskr.model import URL
                            url_obj = URL.query.get(url_id)
                            if url_obj:
                                url_obj.monitoring_active = False
                                db.session.commit()
                                socketio.emit(emit_event, {
                                    'url_id': temp_id,
                                    'url': url,
                                    'url_status': current_status,
                                    'last_success_time': None,
                                    "monitoring_active": False
                                })
                                print("Đã dừng thread do vượt quá giới hạn kết nối cho phép")
                    except Exception as ex:
                        print("Lỗi cập nhật DB: ", ex)
                stop_event.set()
                try:
                    from flask import current_app
                    app = current_app._get_current_object()
                except RuntimeError:
                    app = create_app()
                with app.app_context():
                    send_mail(
                        subject="Mất kết nối với URL.",
                        recipients=['nqdung1977@gmail.com', 'nqdung19082002@gmail.com'],
                        template='mail/email_url_down.html',
                        title="Mất kết nối với URL.",
                        url=url,
                        error_details=e
                    )
        if stop_event.is_set():
            break
        if stop_event.wait(10): # Thời gian chờ giữa các vòng lặp
            break

def detect_waf(url):
    try:
        cmd = ["wafw00f", url, "-o", "waf.json", "-a"]
        subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)
        with open('waf.json', "r", encoding="utf-8") as f:
            data = json.load(f)
        if not data:
            print(f"Không tìm thấy WAF của { url }")
            return None
        return data
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Lỗi khi quét WAF: {e}")
        return None
    
    