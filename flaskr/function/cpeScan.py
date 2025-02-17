#!/usr/bin/env python3
import os
import json
import time
import sys
import re

from tqdm import tqdm
from whoosh import index
from whoosh.fields import Schema, TEXT, STORED
from whoosh.query import And
from whoosh.qparser import QueryParser
from whoosh.analysis import RegexTokenizer, LowercaseFilter
from whoosh import scoring
from whoosh import highlight

# Đường dẫn đến thư mục chứa data
CPE_JSON_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src/nvd_cpe_data/cpe.json"))
INDEX_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src/nvd_cpe_data/whoosh_indexing"))
CPE_PATTERN = re.compile(
    r"^cpe:2\.3:(?P<part>[aho]):(?P<vendor>[^:]*):(?P<product>[^:]*):(?P<version>[^:]*):(?P<update>[^:]*):(?P<edition>[^:]*):(?P<language>[^:]*):(?P<sw_edition>[^:]*):(?P<target_sw>[^:]*):(?P<target_hw>[^:]*):(?P<other>[^:]*)$"
)

# 0.1. Tạo analyzer cho index, thoát hết tất cả các kí tự đặc biệt, kể cả "/" và "\"
cpe_analyzer = RegexTokenizer(r"[^ \\\/\t\r\n\-_:]+") | LowercaseFilter()

# 1. Tạo schema cho index
schema = Schema(
    vendor_product = TEXT(stored=True, analyzer=cpe_analyzer),
    versions = TEXT(stored=True, analyzer=cpe_analyzer),
    cpe = STORED
)

# 2. Parse dữ liệu từ JSON
def parse_cpe_uri(cpe_uri: str):
    """
    Tách vendor, product, version... từ cpe23Uri dạng:
    cpe:2.3:a:wordpress:wordpress:6.2.1:*:*:*:*:*:*:*
    Trả về (vendor, product, version_str).
    """
    m = CPE_PATTERN.match(cpe_uri.strip())
    if not m:
        return ("", "")  
    vendor_product = f"{m.group("vendor")}:{m.group("product")}"
    # product = m.group("product")
    version = m.group("version")

    return (vendor_product, version)

# 3. Tạo index từ schema
def create_cpe_index():
    start_time = time.time()

    # Tạo thư mục chứa index, nếu đã tồn tại, refresh
    if not os.path.exists(INDEX_DIR):
        os.mkdir(INDEX_DIR)
        ix = index.create_in(INDEX_DIR, schema)
    else:
        for file in os.listdir(INDEX_DIR): 
            os.remove(os.path.join(INDEX_DIR, file))   
        ix = index.create_in(INDEX_DIR, schema)

    # Đọc dữ liệu từ file JSON
    with open(CPE_JSON_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)


    count_index = 0 # Đếm số lượng index
    cpe_universe = ""
    matches = data.get("matches", [])
    with ix.writer() as writer:
        # Lấy dữ liệu từ trường "matches" trong JSON, thêm phần trăm tiến trình
        for i, match in tqdm(enumerate(matches), total=len(matches), desc="Đang Index"):
            cpe_uri_raw = match.get("cpe23Uri", "").strip()
            # Kiểm tra xem cpe khái quát này có trùng với cpe trước không, do cấu trúc lưu cpe
            # có rất nhiều cpe khái quát trùng lặp bởi việc chia dải version.
            # Tuy nhiên có trường hợp không có cpe khái quát cho tất cả phiên bản mà chỉ có cpe của
            # khái quát cho các phiên bản, vì vậy duyệt như này để đảm bảo lấy được đủ cpe của các
            # cả toàn bộ phiên bản và dải phiên bản, dù có nhiều cpe dải phiên bản bị overlap.
            if cpe_uri_raw == cpe_universe:
                continue
            else:
                if (not match.get("versionStartIncluding", "") and 
                    not match.get("versionEndIncluding", "") and 
                    not match.get("versionStartExcluding", "") and 
                    not match.get("versionEndExcluding", "")):
                    cpe_universe = cpe_uri_raw
            
            if not cpe_uri_raw:
                continue

            # Lấy version từ list cpe_name
            vendor_product_cpe, _ = parse_cpe_uri(cpe_uri_raw)
            version_list = []
            if not match.get("cpe_name", []):
                version_field = ["*"]
            else:
                for cpe_versions in match.get("cpe_name", []):
                    _, sub_version = parse_cpe_uri(cpe_versions.get("cpe23Uri","").strip())
                    version_list.append(sub_version)
            version_field = " ".join(version_list)

            writer.add_document(
                vendor_product = vendor_product_cpe,
                versions = version_field,
                cpe = cpe_uri_raw
            )
            count_index += 1

        # Thông báo hoàn thành add document
        pause_time = time.time()
        print(f"Complete adding document time: {pause_time - start_time:.4f} seconds")
        print(f"Start merging segments...")

    # Thông báo hoàn thành index
    stop_time = time.time()
    print(f"Index created/updated: {count_index} CPE entries.")
    print(f"Indexing time: {stop_time - start_time:.4f} seconds")


# 4. Tìm kiếm CPE
def search_cpe(input_product: str, input_version:str, limit):
    if not os.path.exists(INDEX_DIR):
        print("Index directory not found. Please run indexing first.")
        return []

    ix = index.open_dir(INDEX_DIR)

    # Sử dụng BM25F để scoring
    searcher_weighting = scoring.BM25F(k1 = 0.001)
    q = custom_query_parser(input_product, input_version)
    with ix.searcher(weighting=searcher_weighting) as searcher:
        results = searcher.search(q, limit=limit)
        # Lấy danh sách (score, cpe_uri), highlight version được match trên terminal
        # results.fragmenter = highlight.ContextFragmenter(maxchars=100, surround=20)
        # results.formatter = ColorFormatter()
        matched = []
        for hit in results:
            score = hit.score
            cpe_general = hit["cpe"]
            version = input_version
            matched.append((score, cpe_general, version))
        return matched

# Điều chỉnh query parser cho user_input
def custom_query_parser(input_product: str, input_version:str):
    vendor_product_parser = QueryParser("vendor_product", schema=schema)
    version_parser = QueryParser("versions", schema=schema)

    q_product = vendor_product_parser.parse(input_product)
    q_version = version_parser.parse(input_version)

    return And([q_product, q_version])

# Chỉnh màu để highlight trong cmd
class ColorFormatter(highlight.Formatter):
    def format_token(self, text, token, replace=False):
        RED = "\033[91m"
        RESET = "\033[0m"
        return f"{RED}{token.text}{RESET}"
    
# Chuẩn hóa user_input
def normalize_input(user_input: str):
    return user_input.strip().replace(" ", "_")

# Tìm cpe từ user input
def main():
    if len(sys.argv) > 1 and sys.argv[1] == "index":
        create_cpe_index()
        return
    # Mặc định: nhập user_query và search
    user_input_product = normalize_input(input("Nhập tên công nghệ: "))
    user_input_version = normalize_input(input("Nhập phiên bản: "))
    start_time = time.time()
    matched = search_cpe(user_input_product, user_input_version, limit=5)
    print(matched)
    end_time = time.time()

    print(f"\nTìm thấy {len(matched)} kết quả:")
    for score, cpe_uri, version in matched:
        print(f"[score={score:.3f}] {cpe_uri}")
        print(f"    Highlighted version: {version} \n")
    print(f"Thời gian tìm kiếm: {end_time - start_time:.4f} giây")

if __name__ == "__main__":
    main()
