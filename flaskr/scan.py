import subprocess
import json
import os
import requests
import threading
from . import socketio
from flask_socketio import emit
from flaskr.auth import login_required
from flask import Blueprint, flash, render_template, request, jsonify

bp = Blueprint('scan', __name__)
LOG_FILE = "log.json"  

# Khai báo các biến toàn cục cho việc kiểm soát thread
current_thread = None
stop_event = threading.Event()
url_status = None

def check_url_status(url, stop_event):
    global url_status
    err_count = 0
    last_status = None
    # Vòng lặp chạy cho đến khi stop_event được set
    while not stop_event.is_set():
        try:
            response = requests.get(url)
            url_status = response.status_code
            emit_data = {'url_status': url_status}
            socketio.emit('status_update', emit_data)
            print(f"Status của {url}: {url_status}")
            err_count = 0
            last_status = url_status
        # Xử lý lỗi kết nối
        except requests.RequestException as e:
            err_count += 1
            err_log = str(e)
            print(f"Lỗi khi kiểm tra {url}: {err_log}")
            url_status = "{} (Lỗi kết nối {} lần)".format(last_status, err_count)
            emit_data = {'url_status': url_status}
            socketio.emit('status_update', emit_data)
            if err_count >= 3:
                socketio.emit('error', {'message': f"Lỗi khi kiểm tra {url}: {err_log}"})
        if stop_event.wait(5):
            break  # Nếu stop_event được set trong thời gian chờ, thoát vòng lặp

@bp.route('/', methods=['GET', 'POST'])
@login_required
def tech_scan():
    global url_status, current_thread, stop_event
    results = None

    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            # Đóng thread cũ và chạy thread mới
            if current_thread and current_thread.is_alive():
                stop_event.set()        # Báo hiệu cho thread cũ dừng
                current_thread.join()   # Chờ thread cũ kết thúc
                print("Đã kết thúc thread cũ")
                stop_event.clear()      # Reset lại event để sử dụng cho thread mới

            try:
                # Khởi tạo và chạy thread mới với stop_event được truyền vào
                current_thread = threading.Thread(target=check_url_status, args=(url, stop_event), daemon=True)
                current_thread.start()

                # Chạy Wappalyzer để quét công nghệ
                cmd = ["wappalyzer", "-i", url, "-oJ", LOG_FILE]
                subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)

                if os.path.exists(LOG_FILE):
                    with open(LOG_FILE, "r", encoding="utf-8") as f:
                        results = json.load(f)
                    with open(LOG_FILE, "w", encoding="utf-8") as f:
                        f.write(json.dumps(results, indent=4))
                    # os.remove(LOG_FILE)
                else:
                    flash("Không thể tạo log.json. Kiểm tra Wappalyzer.")
            except Exception as e:
                flash(f"Lỗi khi quét: {e}")

        # Nếu request đến từ AJAX, trả về kết quả riêng
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return render_template('scan/tech-scan-result.html', results=results, url_status=url_status)

    return render_template('scan/tech-scan.html', results=results, url_status=url_status)

@bp.route('/stop-status', methods=['POST'])
@login_required
def stop_status():
    global stop_event
    stop_event.set()  # Dừng thread đang chạy
    print("Đã dừng thread")
    return jsonify(success=True)
