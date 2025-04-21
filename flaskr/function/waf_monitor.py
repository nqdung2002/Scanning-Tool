import threading, subprocess, json, os, tempfile
from datetime import datetime
from flask import current_app
from flaskr.model import URL, WAF, User
from flaskr import db, socketio
from .send_email import send_mail

waf_monitor_threads = {}  # {url_id: (thread, stop_event)}
TOR_PROXIES =  os.getenv("SOCKS_PROXY", "socks5h://127.0.0.1:9050")

def monitor_waf_for_url(url_id):
    stop_event = threading.Event()
    app = current_app._get_current_object()
    retry_count = 0
    max_retries = 5

    def waf_monitor_task():
        nonlocal retry_count
        while not stop_event.is_set():
            with app.app_context():
                url_obj = URL.query.get(url_id)
                if not url_obj or not url_obj.monitoring_active:
                    print(f"URL {url_id} không còn được monitor. Dừng monitor WAF.")
                    break

                # Gọi hàm detect_waf để quét WAF
                print(f"Bắt đầu thread monitor của WAF thuộc url { url_id }")
                waf_results = detect_waf(url_obj.url)
                existing_wafs = WAF.query.filter_by(url_id=url_id).all()
                existing_waf_names = {waf.name for waf in existing_wafs}

                # Thêm nếu phát hiện WAF mới
                if waf_results:
                    for item in waf_results:
                        if item["detected"]:
                            waf_name = item["firewall"]
                            waf_manufacturer = item["manufacturer"]
                            # Bỏ qua các waf không xác định được (Generic)
                            if waf_name.lower() == "generic" and waf_manufacturer.lower() == "unknown":
                                print(f"Bỏ qua WAF 'Generic' với vendor 'Unknown' cho URL {url_obj.url}")
                                continue
                            if waf_name not in existing_waf_names:
                                # Thêm WAF mới vào cơ sở dữ liệu
                                new_waf = WAF(
                                    url_id=url_id,
                                    name=waf_name,
                                    manufacturer=waf_manufacturer,
                                    status=True  # WAF mới được phát hiện là online
                                )
                                db.session.add(new_waf)
                                db.session.commit()
                                print(f"Đã thêm WAF mới: {waf_name} cho URL {url_id}")
                                socketio.emit('add_new_waf')

                for waf in existing_wafs:
                    # Nếu waf.name không có trong danh sách waf vừa được quét
                    if waf.name not in [item["firewall"] for item in waf_results if item["detected"]] and waf.status == True:
                        retry_count += 1

                        # Nếu sau max_retries mà WAF vẫn offline, cập nhật trạng thái và gửi email
                        if retry_count >= max_retries:
                            waf.status = False
                            from ..monitor import add_alert
                            alert_id = add_alert(
                                url_id=url_id,
                                alert_type='waf_offline',
                                title=f'WAF { waf.id } đã offline',
                                content=f"WAF { waf.name } của URL { url_obj.url } đã offline!"
                            )
                            db.session.commit()
                            print(f"WAF {waf.name} đã offline cho URL {url_id} sau {max_retries} lần thử.")
                            socketio.emit('notification_push', {
                                'alert_id': alert_id,
                                'url_id': url_id,
                                'url': URL.query.filter_by(id=url_id).first().url,
                                'alert_type': 'waf_offline',
                                'title': f'WAF { waf.id } đã offline',
                                'content': f"WAF { waf.name } của URL { url_obj.url } đã offline!" 
                            })
                            send_mail(
                                subject=f"WAF {waf.name} đã offline",
                                recipients=[user.username for user in User.query.all()],
                                template='mail/email_waf_down.html',
                                title=f"WAF {waf.name} của URL {url_id} đã offline",
                                url=url_obj.url
                            )
                        else:
                            print(f"Lấy dữ liệu đến WAF { waf.name } của URL { url_id } thất bại { retry_count }/{ max_retries }. Đang thử lại...")
                    else:
                        # Cập nhật trạng thái khi WAF online lại
                        if not waf.status:
                            waf.status = True
                            db.session.commit()
                            print(f"WAF {waf.name} đã online trở lại cho URL {url_id}")
                            retry_count = 0
                    waf_status = 'Online' if waf.status else 'Offline'
                    socketio.emit('waf_status_update', {
                        'waf_id': waf.id,
                        'waf_status': waf_status,
                        'last_success_time': datetime.now().strftime("%d-%m-%Y %H:%M:%S")
                    })
            stop_event.wait(60) # Thời gian chờ trong thread
    try:
        thread = threading.Thread(target=waf_monitor_task, daemon=True)
        waf_monitor_threads[url_id] = (thread, stop_event)
        thread.start()
    except:
        print("lỗi!!!!!")

def stop_monitoring_waf_for_url(url_id):
    if url_id in waf_monitor_threads:
        thread, stop_event = waf_monitor_threads[url_id]
        stop_event.set()
        thread.join()
        del waf_monitor_threads[url_id]
        print(f"Đã dừng monitor WAF cho URL {url_id}")

def start_monitoring_waf():
    urls = URL.query.filter_by(monitoring_active=True).all()
    for url_obj in urls:
        if url_obj.id not in waf_monitor_threads:
            monitor_waf_for_url(url_obj.id)

def detect_waf(url):
    try:
        # Tạo tệp temp để wafw00f lưu ra kết quả
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as temp_file:
            temp_file_path = temp_file.name
        cmd = ["wafw00f", url, "-o", temp_file_path, "-p", TOR_PROXIES]
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        with open(temp_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        import os
        os.remove(temp_file_path)
        if not data:
            print(f"Không tìm thấy WAF của { url }")
            return []
        return data
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Lỗi khi quét WAF: {e}")
        return []