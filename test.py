#!/usr/bin/env python3
import os
import json
import time
import sys
import re

from whoosh import index
from whoosh.fields import Schema, TEXT, ID
from whoosh.filedb.filestore import FileStorage
from whoosh.qparser import MultifieldParser
from whoosh.analysis import RegexTokenizer, LowercaseFilter
from whoosh import scoring

CPE_JSON_FILE = "cpe_test.json"
CPE_PATTERN = re.compile(
    r"^cpe:2\.3:(?P<part>[aho]):(?P<vendor>[^:]*):(?P<product>[^:]*):(?P<version>[^:]*):(?P<update>[^:]*):(?P<edition>[^:]*):(?P<language>[^:]*):(?P<sw_edition>[^:]*):(?P<target_sw>[^:]*):(?P<target_hw>[^:]*):(?P<other>[^:]*)$"
)

# 1. Tạo schema cho index
schema = Schema(
    cpe_id = ID(stored=True),
    vendor = TEXT(stored=True),
    product = TEXT(stored=True),
    version = TEXT(stored=True),
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
        return ("", "", "", cpe_uri)  # trả về cả cpe_uri phòng hờ
    vendor = m.group("vendor")
    product = m.group("product")
    version = m.group("version")

    return (vendor, product, version, cpe_uri)

# 3. Tạo index từ schema
def create_index():
    INDEX_DIR = "cpe"
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

    count_index = 0
    matches = data.get("matches", [])
    writer = ix.writer()
    for cpe_main_raw, match in enumerate(matches):
        cpe_uri_main = match.get("cpe23Uri", "").strip()
        if not cpe_uri_main:
            continue
        vendor, product, version, cpe_uri = parse_cpe_uri(cpe_uri_main)
        writer.add_document(
            cpe_id = str(cpe_main_raw),
            vendor = vendor,
            product = product,
            version = version,
            cpe = cpe_uri
        )
        count_index += 1
        cpe_detail_list = match.get("cpe_name", [])
        for cpe_detail_raw, cpe_detail in enumerate(cpe_detail_list):
            cpe_uri_detail = cpe_detail.get("cpe23Uri", "").strip()
            if not cpe_uri_detail:
                continue
            vendor, product, version, cpe_uri = parse_cpe_uri(cpe_uri_detail)
            writer.add_document(
                cpe_id = f"{cpe_main_raw}-{cpe_detail_raw}",
                vendor = vendor,
                product = product,
                version = version,
                cpe = cpe_uri
            )
            count_index += 1
    writer.commit()
    print(f"Index created/updated: {count_index} CPE entries.")

def adding_document():

def main():
    # Nếu chạy: python whoosh_cpe_custom.py index => tạo index
    if len(sys.argv) > 1 and sys.argv[1] == "index":
        create_index()
        return

if __name__ == "__main__":
    main()
