import threading, subprocess, json
from datetime import datetime
from flask import current_app
from flaskr.model import URL, WAF
from flaskr import db, socketio
from .send_email import send_mail

waf_monitor_threads = {}  # {url_id: (thread, stop_event)}

def monitor_waf_for_url(url_id):
    stop_event = threading.Event()
    app = current_app._get_current_object()
    retry_count = 0
    max_retries = 3

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

                for waf in existing_wafs:
                    # Nếu waf.name không có trong danh sách waf vừa được quét
                    if waf.name not in [item["firewall"] for item in waf_results if item["detected"]] and waf.status == True:
                        retry_count += 1

                        # Nếu sau max_retries mà WAF vẫn offline, cập nhật trạng thái và gửi email
                        if retry_count >= max_retries:
                            waf.status = False
                            db.session.commit()
                            print(f"WAF {waf.name} đã offline cho URL {url_id} sau {max_retries} lần thử.")
                            send_mail(
                                subject=f"WAF {waf.name} đã offline",
                                recipients=['nqdung19082002@gmail.com'],
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
        cmd = ["wafw00f", url, "-o", "waf.json", "-a"]
        subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)
        with open('waf.json', "r", encoding="utf-8") as f:
            data = json.load(f)
        if not data:
            print(f"Không tìm thấy WAF của { url }")
            return []
        return data
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Lỗi khi quét WAF: {e}")
        return []