import subprocess, json, os, threading, tempfile
from flask import Blueprint, flash, render_template, request, jsonify, current_app
from flaskr.auth import login_required
from flaskr import socketio
from flaskr.function.nuclei_scan import check_template_available, run_nuclei, analyze_results
from flaskr.function.cpe_scan import search_cpe
from flaskr.function.cve_scan import create_cve_list
from flaskr.function.url_monitor import check_url_status
from flaskr.function.waf_monitor import detect_waf
from concurrent.futures import ThreadPoolExecutor

bp = Blueprint('scan', __name__)

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

    if request.method == 'POST':
        scanning_url = request.form.get('url').strip()
        if scanning_url:
            # Check có waf không
            list_wafs = check_waf(scanning_url)

            # Nếu có thread scan cũ đang chạy thì dừng nó
            if current_scan_thread and current_scan_thread.is_alive():
                scan_stop_event.set()
                current_scan_thread.join()
                print("Đã kết thúc thread scan cũ")
            scan_stop_event = threading.Event()
            results = check_tech(scanning_url)
            
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

def check_waf (url):
    list_wafs = []
    try:
        print(f"Bắt đầu check WAF của { url }")
        waf_results = detect_waf(url)
        if waf_results:
            for item in waf_results:
                if item["detected"] == True:
                    waf_name = item["firewall"]
                    waf_manufacturer = item["manufacturer"]
                    if waf_name.lower() == "generic" and waf_manufacturer.lower() == "unknown":
                        list_wafs.append((item["manufacturer"], item["firewall"]))
    except subprocess.SubprocessError as e:
        print(f"Có lỗi xảy ra với wafw00f: { e }")
    return list_wafs

def check_tech(url):
    results = None
    retries = 0
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as temp_file:
            temp_file_path = temp_file.name
        cmd = ["wappalyzer", "-i", url, "-oJ", temp_file_path]
        subprocess.run(cmd, capture_output=True, text=True, check=True)

        if os.path.exists(temp_file_path):
            with open(temp_file_path, "r", encoding="utf-8") as f:
                results = json.load(f)
            os.remove(temp_file_path) # Xóa sau khi sử dụng
            print("Quét thành công")
        else:
            flash("Không thể tạo log.json. Kiểm tra Wappalyzer.")
            print("Không thể tạo log.json. Kiểm tra Wappalyzer.")
    except subprocess.CalledProcessError as e:
        retries += 1
        print(f"Lỗi khi quét: {e}")
    return results

# endpoint để dừng kiểm tra status thủ công trên giao diện
@bp.route('/stop-status', methods=['POST'])
@login_required
def stop_status():
    global scan_stop_event
    scan_stop_event.set()
    print("Đã dừng thread scan")
    return jsonify(success=True)

@bp.route('/cpe-check', methods=['POST'])
def cpe_scan():
    cpe_list = []
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
    output_file = "scan-results.json"
    available_templates, missing_templates = check_template_available(cves)
    results = {}

    if available_templates:
        for template in available_templates:
            results[template] = {
                "status": "Có template nhưng không phát hiện lỗ hổng",
            }
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

# Biến kiểm soát tiến trình
step_lock = threading.Lock()
curr_step = 0
steps_per_url = 4
total_steps = 0

@bp.route('/quick_add_to_monitor', methods=['POST'])
def quick_add():
    file = request.files.get('file')
    if not file:
        return jsonify({"error": "No file provided"}), 400

    urls = file.read().decode('utf-8').splitlines()

    # Khởi tạo tổng số step và reset số step hiện tại
    global current_step, total_steps
    current_step = 0
    total_steps   = len(urls) * steps_per_url

    # Sử dụng ThreadPoolExecutor để xử lý song song
    results = []
    app = current_app._get_current_object()
    with ThreadPoolExecutor(max_workers=5) as executor:  # Tùy chỉnh số lượng luồng (max_workers)
        futures = [executor.submit(process_url, url, app) for url in urls]
        for future in futures:
            results.append(future.result())
    print(f">>>>>>>>>> Hoàn thành thêm {len(urls)} vào danh sách monitoring!!! <<<<<<<<<<")
    return jsonify({"message": "Processing completed", "results": results}), 200

def report_step():
    global current_step, total_steps
    with step_lock:
        current_step += 1
        pct = round(current_step / total_steps * 100, 2)
    socketio.emit('global_progress', {'progress': pct})

def process_url(url, app):
    url = url.strip()
    if not url:
        return {"url": url, "error": "URL is empty"}

    print(f"Target: {url}")

    with app.app_context():
        try:
            # 1. Lấy WAF
            print(f"----------1. Lấy Waf-----------")
            list_wafs = check_waf(url)
            report_step()

            # 2. Lấy tech bằng wappalyzer
            print(f"----------2. Tìm công nghệ-----------")
            list_techs = check_tech(url)
            tech_with_versions = []
            for tech, details in list_techs.get(url, {}).items():
                if details.get('version'):
                    tech_with_versions.append([tech, details['version']])
            report_step()

            # 3. Lấy CPE và CVE
            print(f"----------3. Tìm CPE và CVE-----------")
            results = []
            for tech, version in tech_with_versions:
                try:
                    cpe_obj = search_cpe(tech, version, 1)
                except Exception as e:
                    print(f"Lỗi khi tìm CPE: {e}")
                    continue
                if not cpe_obj:
                    continue
                _, cpe, _ = cpe_obj[0]

                raw_cves = create_cve_list(cpe, version, 100)
                formatted_cves = []
                for item in raw_cves:
                    if isinstance(item, dict):
                        formatted_cves.append(item)
                    else:
                        (cve, cwe, desc, vec, baseScore,
                        baseSeverity, explScore, impScore, *rest) = item + (None,) * (9 - len(item))
                        formatted_cves.append({
                            "cve": cve,
                            "cwe": cwe,
                            "description": desc,
                            "vectorString": vec,
                            "baseScore": baseScore,
                            "baseSeverity": baseSeverity,
                            "exploitabilityScore": explScore,
                            "impactScore": impScore,
                            "nucleiResult": None
                        })

                # 4. Lấy danh sách Nuclei
                cve_ids = [e["cve"] for e in formatted_cves]
                nuclei_results = nuclei_scan(cve_ids, url)
                for entry in formatted_cves:
                    entry["nucleiResult"] = (
                        nuclei_results.get(entry["cve"], {}).get("status", "Không tìm thấy template")
                    )

                # 5. Chuẩn hóa dữ liệu
                results.append({
                    "tech": tech,
                    "version": version,
                    "cpe": cpe,
                    "cves": formatted_cves
                })

            # Chuẩn bị dữ liệu để gọi add_to_database
            data = {
                "url": url,
                "results": results,
                "wafs": list_wafs
            }
            report_step()

            # 6. Gọi hàm add_to_database() từ monitor.py
            from flaskr.monitor import add_to_database
            print("Bắt đầu thêm vào cơ sở dữ liệu")
            response = add_to_database(data)
            print(response)
            report_step()

            return {"url": url, "status": "success"}

        except Exception as e:
            print(f"Đã xảy ra lỗi khi xử lý URL {url}: {e}")
            return {"url": url, "error": str(e)}
