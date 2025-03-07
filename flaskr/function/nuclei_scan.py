import subprocess
import os
import json
from pathlib import Path

template_folder_path = Path("C:/Users/Admin/nuclei-templates/http")

def check_template_available(cves):
    available_templates = []
    missing_templates = []
    
    for cve in cves:
        template_name = f"{cve}.yaml"
        found = False
        for file in template_folder_path.rglob(template_name):
            available_templates.append(cve)
            found = True
        if not found:
            missing_templates.append(cve)
    
    return available_templates, missing_templates

def run_nuclei(url, available_templates, output_file):
    templates = []
    for cve in available_templates:
        year = str(cve).split('-')[1]
        template = f"cves/{year}/{cve}.yaml"
        templates.append(template)
    try:
        result = subprocess.run(
            ["nuclei", "-u", url, "-t", ",".join(templates), "-j", "-o", output_file, "-system-resolvers"],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.stdout, e.stderr

def analyze_results(output_file, templates):
    # Khởi tạo kết quả mặc định cho mỗi template
    results = {template: "Có template nhưng không phát hiện ra lỗ hổng" for template in templates}

    if not os.path.exists(output_file):
        return {template: "Có template nhưng không tồn tại lỗ hổng" for template in templates}
    
    entries = []
    # Đọc file theo từng dòng vì nuclei xuất ra file dạng newline-delimited JSON
    with open(output_file, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                entries.append(entry)
            except json.JSONDecodeError:
                # Nếu một dòng không phải JSON hợp lệ, cập nhật lỗi cho tất cả template
                for template in templates:
                    results[template] = "Tệp JSON không hợp lệ hoặc chứa lỗi"
                return results

    if not entries:
        return results

    for entry in entries:
        # Sử dụng key "template-id" thay vì "templateID"
        if "template-id" in entry:
            template_id = entry["template-id"]
            for template in templates:
                expected_id = os.path.splitext(os.path.basename(template))[0]
                if template_id == expected_id:
                    results[template] = "Có tồn tại lỗ hổng"
        else:
            # Nếu không có "template-id", có thể là thông báo lỗi/cảnh báo
            if "msg" in entry:
                error_message = entry["msg"]
                for template in templates:
                    results[template] = f"Lỗi: {error_message}"
    
    return results

