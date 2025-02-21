import os
import gzip
import hashlib
import requests
import datetime
from tqdm import tqdm
from pathlib import Path
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

NVD_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1"
BASE_DIR = (Path(__file__).resolve().parent / "../../src").resolve()
CVE_DATA_DIR = BASE_DIR / "nvd_cve_data"
CPE_DATA_DIR = BASE_DIR / "nvd_cpe_data"

# Set đường dẫn
def get_local_paths(target: str):
    if target == "cpe":
        filename_base = "nvdcpematch-1.0"
        data_dir = CPE_DATA_DIR
    else:
        filename_base = f"nvdcve-1.1-{target}"
        data_dir = CVE_DATA_DIR
    data_dir.mkdir(parents=True, exist_ok=True)
    return {
        "filename_base": filename_base,
        "local_gz_path": data_dir / f"{filename_base}.json.gz",
        "local_meta_path": data_dir / f"{filename_base}.meta",
        "local_json_path": data_dir / f"{filename_base}.json",
    }

# tạo session để tải dữ liệu
def create_session(retries=5, backoff_factor=1.0, status_forcelist=(500, 502, 503, 504)):
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

SESSION = create_session()

# tải dữ liệu và xử lý lỗi khi tải
def download_and_retry(url, chunk_size=1024, timeout=240):
    try:
        response = SESSION.get(url, stream=True, timeout=timeout)
        response.raise_for_status()
        total_length = response.headers.get('content-length')
        if total_length is None:
            print("Không biết kích thước file, tải toàn bộ dữ liệu...")
            return response.content
        total_length = int(total_length)
        data = bytearray()
        with tqdm(total=total_length, unit='B', unit_scale=True, desc="Downloading", dynamic_ncols=True) as pbar:
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:
                    data.extend(chunk)
                    pbar.update(len(chunk))
        return bytes(data)
    except Exception as e:
        print(f"[ERROR] Lỗi tải {url}: {e}")
        return None

def sha256_of_bytes(data: bytes) -> str:
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data)
    return sha256_hash.hexdigest()

# xử lý dữ liệu
def handle_data(target):
    paths = get_local_paths(target)
    filename_base = paths["filename_base"]
    gz_url = f"{NVD_BASE_URL}/{filename_base}.json.gz"
    meta_url = f"{NVD_BASE_URL}/{filename_base}.meta"
    if target == "cpe":
        gz_url = "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.json.gz"
        meta_url = "https://nvd.nist.gov/feeds/json/cpematch/1.0/nvdcpematch-1.0.meta"

    # Tải file .gz và ghi vào đĩa
    print(f"[INFO] Tải file nén: {gz_url}")
    gz_data = download_and_retry(gz_url)
    if gz_data is None:
        print(f"[ERROR] Không thể tải xuống {gz_url}")
        return False
    with open(paths["local_gz_path"], "wb") as f:
        f.write(gz_data)

    try:
        uncompressed_data = gzip.decompress(gz_data)
    except Exception as e:
        print(f"[ERROR] Lỗi giải nén (in-memory) {paths['local_gz_path']}: {e}")
        return False

    # Tải file .meta và ghi vào đĩa
    print(f"[INFO] Tải file meta: {meta_url}")
    meta_data = download_and_retry(meta_url)
    if meta_data is None:
        print(f"[ERROR] Không thể tải xuống {meta_url}")
        return False
    with open(paths["local_meta_path"], "wb") as f:
        f.write(meta_data)

    # Lấy sha256 từ file meta
    expected_sha256 = None
    try:
        meta_lines = meta_data.decode("utf-8").splitlines()
        for line in meta_lines:
            if line.lower().startswith("sha256:"):
                _, value = line.split(":", 1)
                expected_sha256 = value.strip()
                break
    except Exception as e:
        print(f"[ERROR] Lỗi đọc file meta {paths['local_meta_path']}: {e}")
        return False

    if not expected_sha256:
        print(f"[ERROR] Không tìm thấy SHA256 trong file meta của {filename_base}")
        return False

    actual_sha256 = sha256_of_bytes(uncompressed_data)
    if actual_sha256.lower() != expected_sha256.lower():
        print(f"[ERROR] SHA256 không khớp cho {filename_base}")
        print(f"       Dự kiến: {expected_sha256}")
        print(f"       Thực tế: {actual_sha256}")
        return False

    print(f"[INFO] Đã xác nhận SHA256 cho {filename_base}")

    # Ghi dữ liệu JSON đã giải nén và xóa file tạm thời
    try:
        with open(paths["local_json_path"], "wb") as f:
            f.write(uncompressed_data)
        print(f"[INFO] Đã ghi file {paths['local_json_path']}")
        paths["local_gz_path"].unlink()
        paths["local_meta_path"].unlink()
    except Exception as e:
        print(f"[ERROR] Lỗi ghi file JSON {paths['local_json_path']}: {e}")
        return False
    return True

def pulling(targets):
    for target in targets:
        print(f"\n=== Xử lý dữ liệu cho {target} ===")
        if not handle_data(target):
            print(f"[ERROR] Tải / xác minh dữ liệu {target} thất bại.")
        else:
            print(f"[INFO] Hoàn tất dữ liệu {target}.\n")

def complete_pull():
    targets = list(range(2002, 2026)) + ["modified", "recent", "cpe"]
    pulling(targets)

def modified_recent_pull():
    targets = ["modified", "recent"]
    pulling(targets)

if __name__ == '__main__':
    modified_recent_pull()
