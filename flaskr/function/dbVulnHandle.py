import requests
import time
import json

# Cấu hình API của NVD
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = "4fc5fc94-2fc4-42e2-892b-15bca07d559"

def fetch_cve_data(start_index=0, results_per_page=1):
    """
    Gọi API NVD để lấy một trang dữ liệu CVE.
    """
    params = {
        'resultsPerPage': results_per_page,
        'startIndex': start_index,
        # Bạn có thể giới hạn theo thời gian nếu cần, ví dụ:
        # 'pubStartDate': '2020-01-01T00:00:00.000',
        # 'pubEndDate': '2025-01-01T00:00:00.000'
    }
    headers = {'apiKey': API_KEY}
    response = requests.get(API_URL, params=params, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print("Lỗi API: ", response.status_code)
        return None
    

def initial_pull():
    """
    Lấy toàn bộ dữ liệu CVE bằng cách phân trang.
    """
    start_index = 0
    results_per_page = 2000  # Số lượng CVE mỗi trang (tuỳ thuộc giới hạn API)
    total_results = None

    all_cve_items = []  # Danh sách chứa tất cả CVE được lấy về

    while True:
        print(f"[INFO] Lấy dữ liệu từ startIndex = {start_index}")
        data = fetch_cve_data(start_index, results_per_page)
        if not data:
            break

        # Số CVE trong kết quả trả về
        cve_items = data.get('vulnerabilities', [])
        if not cve_items:
            print("[INFO] Không còn dữ liệu trả về.")
            break

        all_cve_items.extend(cve_items)

        if total_results is None:
            total_results = data.get('totalResults', 0)
            print(f"[INFO] Tổng số CVE theo API: {total_results}")

        start_index += results_per_page
        if start_index >= total_results:
            print("[INFO] Đã lấy hết dữ liệu.")
            break

        time.sleep(6)  # Nghỉ 1 giây để tránh rate-limit

    # Lưu dữ liệu vào file để dùng cho bước sau (nếu cần)
    with open("nvd_cve_data.json", "w", encoding="utf-8") as f:
        json.dump(all_cve_items, f, ensure_ascii=False, indent=2)
    print(f"[INFO] Đã lưu {len(all_cve_items)} CVE vào file nvd_cve_data.json")
    return all_cve_items

if __name__ == '__main__':
    initial_pull()
