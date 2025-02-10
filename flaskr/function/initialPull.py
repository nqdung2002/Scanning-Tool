import os
import gzip
import hashlib
import requests
import datetime

"""
Chạy script này để khởi tạo dữ liệu CVE từ NVD Data Feeds.
"""

NVD_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1"
DATA_DIR = os.path.join(os.getcwd(), "src", "nvd_cve_data")

def handle_data(year):
    filename_base = f"nvdcve-1.1-{year}"
    gz_url = f"{NVD_BASE_URL}/{filename_base}.json.gz"
    meta_url = f"{NVD_BASE_URL}/{filename_base}.meta"
    
    local_gz_path = os.path.join(DATA_DIR, f"{filename_base}.json.gz")
    local_meta_path = os.path.join(DATA_DIR, f"{filename_base}.meta")
    local_json_path = os.path.join(DATA_DIR, f"{filename_base}.json")

    # Tải file .gz và giải nén ra file .json
    print(f"[INFO] Tải file nén: {gz_url}")
    r_gz = download_and_retry(gz_url)
    with open(local_gz_path, "wb") as f:
        f.write(r_gz.content)
    try:
        with open(local_gz_path, "rb") as f_gz:
            gz_data = f_gz.read()
        uncompressed_data = gzip.decompress(gz_data)
    except Exception as e:
        print(f"[ERROR] Lỗi giải nén (in-memory) {local_gz_path}: {e}")
        return False

    # Tải file .meta
    print(f"[INFO] Tải file meta: {meta_url}")
    r_meta = download_and_retry(meta_url)
    with open(local_meta_path, "wb") as f:
        f.write(r_meta.content)

    # lấy sha256 từ file meta
    meta_lines = r_meta.text.splitlines()
    expected_sha256 = None
    for line in meta_lines:
        if line.lower().startswith("sha256:"):
            parts = line.split(":", 1)
            if len(parts) == 2:
                expected_sha256 = parts[1].strip()
            break
    if not expected_sha256:
        print(f"[ERROR] Không tìm thấy SHA256 trong file meta của {filename_base}")
        return False

    # Tính SHA256 của dữ liệu JSON đã giải nén và so sánh sha256
    actual_sha256 = sha256_of_bytes(uncompressed_data)
    if actual_sha256.lower() != expected_sha256.lower():
        print(f"[ERROR] SHA256 không khớp cho {filename_base}")
        print(f"       Dự kiến: {expected_sha256}")
        print(f"       Thực tế: {actual_sha256}")
        return False
    print(f"[INFO] Đã xác nhận SHA256 cho {filename_base}")

    # Ghi dữ liệu JSON đã giải nén ra file .json, xóa file .gz và .meta
    try:
        with open(local_json_path, "wb") as f_json:
            f_json.write(uncompressed_data)
        print(f"[INFO] Đã ghi file {local_json_path}")
        os.remove(local_gz_path)
        os.remove(local_meta_path)
    except Exception as e:
        print(f"[ERROR] Lỗi ghi file JSON {local_json_path}: {e}")
        return False
    return True

# Tải file và thử lại để tránh lỗi Connection Aborted
def download_and_retry (url, retries=5):
    for i in range(retries):
        try:
            r = requests.get(url, timeout=240)
            r.raise_for_status()
            return r
        except Exception as e:
            print(f"[ERROR] Lỗi tải {url}: {e}")
            if i < retries - 1:
                print(f"[INFO] Thử lại lần {i + 1}...")
    return None

# Tính sha256 của data
def sha256_of_bytes(data: bytes) -> str:
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data)
    return sha256_hash.hexdigest()

def initial_pull():
    os.makedirs(DATA_DIR, exist_ok=True)
    years = range(2002, 2026) 
    for year in years:
        print(f"\n=== Xử lý dữ liệu cho năm {year} ===")
        succeeded = handle_data(year)
        if not succeeded:
            print(f"[ERROR] Tải / xác minh dữ liệu năm {year} thất bại.")
        else:
            print(f"[INFO] Hoàn tất dữ liệu năm {year}.\n")

    completion_time = datetime.datetime.now().isoformat() + "Z"
    print(f"\n[INFO] Initial pull hoàn tất lúc: {completion_time}")

if __name__ == '__main__':
    initial_pull()
