import subprocess
import json
import os
import threading
import time
from flask import Blueprint, flash, render_template, request, jsonify
from flaskr.auth import login_required
from flaskr import socketio
from flaskr.function.nuclei_scan import check_template_available, run_nuclei, analyze_results
from flaskr.function.cpe_scan import search_cpe
from flaskr.function.cve_scan import create_cve_list
from flaskr.function.url_monitor import check_url_status, detect_waf  # Sử dụng hàm chung để theo dõi URL

bp = Blueprint('scan', __name__)
LOG_FILE = "log.json"  

# Biến toàn cục dùng cho việc scan
current_scan_thread = None
scan_stop_event = threading.Event()
url_status = None
last_success_time = "Chưa có kết quả"
scanning_url = None
list_wafs = []

@bp.route('/', methods=['GET', 'POST'])
@login_required
def tech_scan():
    global url_status, current_scan_thread, scan_stop_event, scanning_url, list_wafs
    results = None
    list_wafs = []

    if request.method == 'POST':
        scanning_url = request.form.get('url').strip()
        if scanning_url:
            # Check có waf không
            try:
                waf_results = detect_waf(scanning_url)
                if waf_results:
                    for item in waf_results:
                        if item["detected"] == True:
                            list_wafs.append((item["manufacturer"], item["firewall"]))
            except subprocess.SubprocessError as e:
                print(f"Có lỗi xảy ra với wafw00f: { e }")

            # Nếu có thread scan cũ đang chạy thì dừng nó
            if current_scan_thread and current_scan_thread.is_alive():
                scan_stop_event.set()
                current_scan_thread.join()
                print("Đã kết thúc thread scan cũ")
            scan_stop_event = threading.Event()
            retries = 0
            try:
                # Chạy Wappalyzer để quét công nghệ
                cmd = ["wappalyzer", "-i", scanning_url, "-oJ", LOG_FILE]
                subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)

                if os.path.exists(LOG_FILE):
                    with open(LOG_FILE, "r", encoding="utf-8") as f:
                        results = json.load(f)
                    with open(LOG_FILE, "w", encoding="utf-8") as f:
                        f.write(json.dumps(results, indent=4))
                    print("Quét thành công")
                else:
                    flash("Không thể tạo log.json. Kiểm tra Wappalyzer.")
                    print("Không thể tạo log.json. Kiểm tra Wappalyzer.")
            except subprocess.CalledProcessError as e:
                retries += 1
                print(f"Lỗi khi quét: {e}")
            
            # Khởi động thread theo dõi trạng thái URL (với url_id=None vì URL chưa có trong DB)
            try:
                current_scan_thread = threading.Thread(
                    target=check_url_status, args=(scanning_url, scan_stop_event),
                    daemon=True
                )
                current_scan_thread.start()
                print("Thread đã khởi động")
            except:
                print("Lỗi khởi tạo thread")

        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return render_template('scan/tech-scan-result.html', results=results, url_status=url_status, url=scanning_url, wafs=list_wafs)

    return render_template('scan/tech-scan.html', results=results, url_status=url_status, url=scanning_url)

# endpoint để dừng kiểm tra status thủ công trên giao diện
@bp.route('/stop-status', methods=['POST'])
@login_required
def stop_status():
    global scan_stop_event
    scan_stop_event.set()
    print("Đã dừng thread scan")
    return jsonify(success=True)

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
    return render_template('scan/cpe-scan.html', results=cpe_list)

@bp.route('/cve-search', methods=['GET', 'POST'])
def cve_search():
    global scanning_url
    if request.method == 'POST':
        request_list = [value for key, value in request.form.items() if key.startswith('selected_cpe_')]
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
                'cpe': cpe,
                "results": results
            })
        stop_status()
        return render_template('scan/cve-search.html', results=tech_results, url=scanning_url, wafs=list_wafs)
    return render_template('scan/cve-search.html')

@bp.route('/nuclei_scan', methods=['POST'])
def nuclei_scan_route():
    global scanning_url
    data = request.json
    cves = data['cves']
    results = nuclei_scan(cves, scanning_url)
    return jsonify(results)

def nuclei_scan(cves, scanning_url):
    available_templates, missing_templates = check_template_available(cves)
    results = {}

    if available_templates:
        for template in available_templates:
            results[template] = {
                "status": "Có template nhưng không phát hiện lỗ hổng",
            }
        output_file = "scan-results.json"
        run_nuclei(scanning_url, available_templates, output_file)
        vulnerability_results = analyze_results(output_file, available_templates)
        for template, status in vulnerability_results.items():
            if status == "Có tồn tại lỗ hổng":
                results[template] = {
                    "status": status,
                }
    for cve in missing_templates:
        results[cve] = {
            "status": "Không tìm thấy template",
        }
    return results
