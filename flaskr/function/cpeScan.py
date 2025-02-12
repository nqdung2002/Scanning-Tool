#!/usr/bin/env python3
import os
import json
import time
import sys
import re

from tqdm import tqdm
from whoosh import index
from whoosh.fields import Schema, TEXT, ID
from whoosh.query import And
from whoosh.qparser import QueryParser
from whoosh.analysis import RegexTokenizer, LowercaseFilter
from whoosh import scoring
from whoosh import highlight

"""
test
"""
# CPE_JSON_FILE = "../../test/cpe_test.json"
# INDEX_DIR = "../../test/cpe_test"
CPE_JSON_FILE = "../../src/nvd_cpe_data/cpe.json"
INDEX_DIR = "../../src/nvd_cpe_data/whoosh_indexing"
CPE_PATTERN = re.compile(
    r"^cpe:2\.3:(?P<part>[aho]):(?P<vendor>[^:]*):(?P<product>[^:]*):(?P<version>[^:]*):(?P<update>[^:]*):(?P<edition>[^:]*):(?P<language>[^:]*):(?P<sw_edition>[^:]*):(?P<target_sw>[^:]*):(?P<target_hw>[^:]*):(?P<other>[^:]*)$"
)

# 0.1. Tạo analyzer cho index, thoát hết tất cả các kí tự đặc biệt, kể cả "/" và "\"
my_analyzer = RegexTokenizer(r"[^ \\\/\t\r\n\-_:]+") | LowercaseFilter()

# 1. Tạo schema cho index
schema = Schema(
    cpe_id = ID(stored=True),
    vendor_product = TEXT(stored=True, analyzer=my_analyzer),
    # vendor = TEXT(stored=True, analyzer=my_analyzer),
    # product = TEXT(stored=True, analyzer=my_analyzer),
    versions = TEXT(stored=True, analyzer=my_analyzer),
    cpe = TEXT(stored=True)
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
def create_index():
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
    previous_cve = ""
    matches = data.get("matches", [])
    with ix.writer() as writer:
        # Lấy dữ liệu từ trường "matches" trong JSON, thêm phần trăm tiến trình
        for i, match in tqdm(enumerate(matches), total=len(matches), desc="Đang Index"):
            # Lấy vendor, product từ cpe23Uri
            cpe_uri_raw = match.get("cpe23Uri", "").strip()
            if not cpe_uri_raw:
                continue

            # Kiểm tra xem cpe khái quát này có trùng với cpe trước không, do cấu trúc lưu cpe
            # có rất nhiều cpe khái quát trùng lặp bởi việc chia dải version
            # Ở đây chỉ cần lưu cpe
            if cpe_uri_raw == previous_cve:
                continue
            else:
                previous_cve = cpe_uri_raw

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
                cpe_id = str(i),
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
def search_cpe(user_input_version: str, user_input_product:str, limit):
    if not os.path.exists(INDEX_DIR):
        print("Index directory not found. Please run indexing first.")
        return []

    ix = index.open_dir(INDEX_DIR)

    # Sử dụng BM25F để scoring
    searcher_weighting = scoring.BM25F(k1 = 0.001)
    q = custom_user_query_parser(user_input_version, user_input_product)
    print(f"Query: {q}")
    with ix.searcher(weighting=searcher_weighting) as searcher:
        results = searcher.search(q, limit=limit)
        # Lấy danh sách (score, cpe_uri), highlight version được match
        results.fragmenter = highlight.ContextFragmenter(maxchars=100, surround=20)
        results.formatter = ColorFormatter()
        matched = []
        for hit in results:
            score = hit.score
            cpe_uri = hit["cpe"]
            highlight_vendor_product = hit.highlights("vendor_product")
            highlight_version = hit.highlights("versions")
            matched.append((score, cpe_uri, highlight_vendor_product, highlight_version))
        return matched

# Điều chỉnh query parser cho user_input
def custom_user_query_parser(user_input_product: str, user_input_version:str):
    vendor_product_parser = QueryParser("vendor_product", schema=schema)
    version_parser = QueryParser("versions", schema=schema)

    q_product = vendor_product_parser.parse(user_input_product)
    q_version = version_parser.parse(user_input_version)

    return And([q_product, q_version])

# Chỉnh màu để highlight
class ColorFormatter(highlight.Formatter):
    def format_token(self, text, token, replace=False):
        RED = "\033[91m"
        RESET = "\033[0m"
        return f"{RED}{token.text}{RESET}"
    
# Chuẩn hóa user_input
def normalize_user_input(user_input: str):
    return user_input.strip().replace(" ", "_")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "index":
        create_index()
        return
    # Mặc định: nhập user_query và search
    user_input_product = normalize_user_input(input("Nhập tên công nghệ: "))
    user_input_version = normalize_user_input(input("Nhập phiên bản: "))
    start_time = time.time()
    matched = search_cpe(user_input_product, user_input_version, limit=5)
    print(matched)
    end_time = time.time()

    print(f"\nTìm thấy {len(matched)} kết quả:")
    for score, cpe_uri, highlight_vendor_product, highlight_version in matched:
        print(f"[score={score:.3f}] {cpe_uri}")
        print(f"    Highlighted product: {highlight_vendor_product}")
        print(f"    Highlighted version: {highlight_version} \n")
    print(f"Thời gian tìm kiếm: {end_time - start_time:.4f} giây")

if __name__ == "__main__":
    main()
