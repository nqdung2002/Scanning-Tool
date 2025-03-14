import requests
import uuid
from datetime import datetime
from flaskr import socketio, db
from requests.adapters import HTTPAdapter, Retry

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

def check_url_status(url, stop_event, url_id=None, monitoring_active=None, emit_event='status_update', app=None):
    """
    Kiểm tra trạng thái của URL và gửi emit qua SocketIO.
    Nếu url_id=None (tức URL chưa được lưu vào DB), sẽ tạo temp id.
    Khi số lỗi vượt quá quy định, thread tự dừng và cập nhật DB (monitoring_active=False).
    """
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
        if stop_event.is_set():
            break
        if stop_event.wait(10): # Thời gian chờ giữa các vòng lặp
            break
