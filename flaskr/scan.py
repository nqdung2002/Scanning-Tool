import subprocess
import json
import os
from flaskr.auth import login_required
from flask import Blueprint, flash, render_template, request, jsonify

bp = Blueprint('scan', __name__)
LOG_FILE = "log.json"  # Tên file lưu kết quả quét

@bp.route('/', methods=['GET', 'POST'])
@login_required
def tech_scan():
    results = None

    if request.method == 'POST':
        url = request.form.get('url')
        print("URL nhận được:", url)

        if url:
            try:
                # Chạy Wappalyzer để quét công nghệ
                cmd = ["wappalyzer", "-i", url, "-oJ", LOG_FILE]
                subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)

                if os.path.exists(LOG_FILE):
                    with open(LOG_FILE, "r", encoding="utf-8") as f:
                        results = json.load(f)
                    os.remove(LOG_FILE)  # Xóa file sau khi đọc xong
                else:
                    flash("Không thể tạo log.json. Kiểm tra Wappalyzer.")

            except Exception as e:
                flash(f"Lỗi khi quét: {e}")

        # Nếu request đến từ AJAX, trả về kết quả riêng
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return render_template('scan/tech-scan-result.html', results=results)

    return render_template('scan/tech-scan.html', results=results)

