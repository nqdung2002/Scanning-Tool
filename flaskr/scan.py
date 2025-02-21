import subprocess
import json
import os
import requests
import threading
from . import socketio
from flask_socketio import emit
from datetime import datetime
from flaskr.auth import login_required
from flask import Blueprint, flash, render_template, request, jsonify
from flaskr.function.cpe_scan import search_cpe
from flaskr.function.cve_scan import create_cve_list

bp = Blueprint('scan', __name__)
LOG_FILE = "log.json"  

# Khai báo các biến toàn cục cho việc kiểm soát thread
url = None
current_thread = None
stop_event = threading.Event()
url_status = None
last_success_time = "Chưa có kết quả"

@bp.route('/', methods=['GET', 'POST'])
@login_required
def tech_scan():
    global url_status, current_thread, stop_event, url
    results = None

    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            # Đóng thread cũ và chạy thread mới
            if current_thread and current_thread.is_alive():
                stop_event.set()        # Báo hiệu cho thread cũ dừng
                current_thread.join()   # Chờ thread cũ kết thúc
                print("Đã kết thúc thread cũ")
            stop_event = threading.Event() 

            try:
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
                
                # Khởi tạo và chạy thread mới với stop_event được truyền vào
                current_thread = threading.Thread(target=check_url_status, args=(url, stop_event), daemon=True)
                current_thread.start()
            except Exception as e:
                flash(f"Lỗi khi quét: {e}")

        # Nếu request đến từ AJAX, trả về kết quả riêng
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return render_template('scan/tech-scan-result.html', results=results, url_status=url_status, url=url)

    return render_template('scan/tech-scan.html', results=results, url_status=url_status, url=url)

@bp.route('/stop-status', methods=['POST'])
@login_required
def stop_status():
    global stop_event
    stop_event.set()  # Dừng thread đang chạy
    print("Đã dừng thread")
    return jsonify(success=True)

def check_url_status(url, stop_event):
    global url_status, last_success_time
    err_count = 0
    last_status = None
    # Vòng lặp chạy cho đến khi stop_event được set
    while not stop_event.is_set():
        try:
            response = requests.head(url)
            url_status = response.status_code
            last_success_time = datetime.now().strftime("%d-%m-%y %H:%M:%S")
            emit_data = {'url_status': url_status, 'last_success_time': last_success_time}
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
            emit_data = {'url_status': url_status, 'last_success_time': last_success_time}
            socketio.emit('status_update', emit_data)
            if err_count >= 5:
                socketio.emit('error', {'message': f"Lỗi khi kiểm tra {url}: {err_log}"})
        if stop_event.wait(10):
            break  # Nếu stop_event được set trong thời gian chờ, thoát vòng lặp

@bp.route('/cpe-check', methods=['GET', 'POST'])
def cpe_scan():
    cpe_list = []
    if request.method == 'POST':
        selected = request.json
    for tech_info in selected:
        tech = tech_info.get('tech')
        version = tech_info.get('version')
        cpe_result = search_cpe(tech, version, 5)
        cpe_list.append((tech, version, cpe_result))
    return render_template('scan/cpe-scan.html', results = cpe_list)

@bp.route('/cve-search', methods=['GET', 'POST'])
def cve_search():
    if request.method == 'POST':
        request_list = [value for key, value in request.form.items() if key.startswith('selected_cpe_')]

        # Định dạng tech|cpe|version
        tech_results = []
        for item in request_list:
            request_detail = item.split('|')
            tech = request_detail[0]
            cpe = request_detail[1]
            version = request_detail[2]
            results = create_cve_list(cpe, version, 100)
            tech_results.append({
                'tech': tech,
                'version': version,
                "results": results
            })
        return render_template('scan/cve-search.html', results = tech_results)
    
    return render_template('scan/cve-search.html')
