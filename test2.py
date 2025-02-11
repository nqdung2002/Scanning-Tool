#!/usr/bin/env python3
import os
import json
import time
import sys
import re

from whoosh import index
from whoosh.fields import Schema, TEXT, ID, STORED, NUMERIC
from whoosh.qparser import MultifieldParser, QueryParser
from whoosh.analysis import StandardAnalyzer
from whoosh import scoring

# -------------------------------
# HÀM PARSE CPE
# -------------------------------
CPE_PATTERN = re.compile(
    r"^cpe:2\.3:(?P<part>[aho]):(?P<vendor>[^:]*):(?P<product>[^:]*):(?P<version>[^:]*):(?P<update>[^:]*):(?P<edition>[^:]*):(?P<language>[^:]*):(?P<sw_edition>[^:]*):(?P<target_sw>[^:]*):(?P<target_hw>[^:]*):(?P<other>[^:]*)$"
)

def parse_cpe_uri(cpe_uri: str):
    """
    Tách vendor, product, version... từ cpe23Uri dạng:
    cpe:2.3:a:wordpress:wordpress:6.2.1:*:*:*:*:*:*:*
    Trả về (vendor, product, version_str).
    """
    m = CPE_PATTERN.match(cpe_uri.strip())
    if not m:
        return ("", "", "", cpe_uri)  # trả về cả cpe_uri phòng hờ
    vendor = m.group("vendor")
    product = m.group("product")
    version = m.group("version")

    return (vendor, product, version, cpe_uri)

# -------------------------------
# CẤU HÌNH
# -------------------------------
CPE_JSON_FILE = "cpe.json"
INDEX_DIR = "whoosh_cpe_index_custom"

# -------------------------------
# TẠO SCHEMA
# -------------------------------
# Ta lưu:
#  - cpe_id (ID duy nhất)
#  - vendor (TEXT)
#  - product (TEXT)
#  - version (TEXT) -> có thể dùng NUMERIC nếu muốn range query
#  - cpe_uri (TEXT, stored=True) -> lưu chuỗi đầy đủ
schema = Schema(
    cpe_id=ID(stored=True, unique=True),
    vendor=TEXT(stored=True, analyzer=StandardAnalyzer()),
    product=TEXT(stored=True, analyzer=StandardAnalyzer()),
    version=TEXT(stored=True),  
    cpe_uri=TEXT(stored=True)
)

# -------------------------------
# INDEXING
# -------------------------------
def create_or_refresh_index():
    """
    Tạo mới hoặc cập nhật chỉ mục Whoosh dựa trên dữ liệu trong cpe.json.
    """
    start_time = time.time()
    if not os.path.exists(INDEX_DIR):
        os.mkdir(INDEX_DIR)
        ix = index.create_in(INDEX_DIR, schema)
    else:
        # Xoá và tạo lại (cho đơn giản)
        for f in os.listdir(INDEX_DIR):
            os.remove(os.path.join(INDEX_DIR, f))
        ix = index.create_in(INDEX_DIR, schema)

    with open(CPE_JSON_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    matches = data.get("matches", [])
    writer = ix.writer()
    for i, match in enumerate(matches):
        cpe_uri_raw = match.get("cpe23Uri", "").strip()
        if not cpe_uri_raw:
            continue
        vendor, product, version, full_cpe = parse_cpe_uri(cpe_uri_raw)
        writer.add_document(
            cpe_id=str(i),
            vendor=vendor,
            product=product,
            version=version,  
            cpe_uri=full_cpe
        )
    writer.commit()

    end_time = time.time()
    print(f"Index created/updated: {len(matches)} CPE entries.")
    print(f"Indexing time: {end_time - start_time:.4f} seconds")

# -------------------------------
# SEARCH
# -------------------------------
def search_cpe(user_query: str, limit=20):
    """
    Tìm kiếm CPE dựa trên user_query (VD: "wordpress 6"),
    dùng MultiFieldParser để match vendor, product, version.
    Sử dụng BM25F để tính điểm.
    """
    if not os.path.exists(INDEX_DIR):
        print("Index directory not found. Please run indexing first.")
        return []

    ix = index.open_dir(INDEX_DIR)

    # Sử dụng BM25F để scoring
    searcher_weighting = scoring.BM25F()

    # 1) Tách user_query => ta vẫn để Whoosh lo tokenize
    #    Hoặc tuỳ chọn parse logic custom (nếu detect con số => version range?)

    # Tạo query parser trên nhiều field: vendor, product, version
    parser = MultifieldParser(["vendor", "product", "version"], schema=ix.schema)

    q = parser.parse(user_query)

    with ix.searcher(weighting=searcher_weighting) as searcher:
        results = searcher.search(q, limit=limit)
        # Lấy danh sách (score, cpe_uri)
        matched = [(hit.score, hit["cpe_uri"]) for hit in results]
        return matched

def main():
    # Nếu chạy: python whoosh_cpe_custom.py index => tạo index
    if len(sys.argv) > 1 and sys.argv[1] == "index":
        create_or_refresh_index()
        return

    # Mặc định: nhập user_query và search
    user_query = input("Nhập tên công nghệ + phiên bản: ").strip()
    start_time = time.time()
    matched = search_cpe(user_query, limit=20)
    end_time = time.time()

    print(f"\nTìm thấy {len(matched)} kết quả cho '{user_query}':")
    for score, cpe_uri in matched:
        print(f"[score={score:.3f}] {cpe_uri}")
    print(f"Thời gian tìm kiếm: {end_time - start_time:.4f} giây")

if __name__ == "__main__":
    main()
