import json
import time
import sys
import subprocess
from pathlib import Path

from tqdm import tqdm
from packaging.version import Version
from whoosh import index
from whoosh.fields import Schema, TEXT, ID, STORED, KEYWORD
from whoosh.query import Term
from whoosh import scoring

# Khai báo đường dẫn đến thư mục chứa data sử dụng pathlib
INDEX_DIR = (Path(__file__).resolve().parent / "../../src/nvd_cve_data/whoosh_indexing").resolve()

# 1. Tạo schema
schema = Schema(
    cve_id=ID(unique=True, stored=True),
    cwe_id=STORED,
    description=STORED,
    vectorString=STORED,
    baseScore=STORED,
    baseSeverity=STORED,
    exploitabilityScore=STORED,
    impactScore=STORED,
    cpe_list=KEYWORD(stored=True, commas=True, lowercase=True),
    cpe_info=STORED
)

# 2. Parse dữ liệu từ JSON
def parse_cve(item):
    # Lấy thông tin CVE và CWE
    cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
    cwe_list = item.get("cve", {}).get("problemtype", {}).get("problemtype_data", [])
    if cwe_list and cwe_list[0].get("description"):
        cwe = cwe_list[0]["description"][0].get("value", "")
    else:
        cwe = ""
    
    # Lấy description
    desc_data = item.get("cve", {}).get("description", {}).get("description_data", [])
    description = desc_data[0].get("value", "") if desc_data else ""
    
    # Lấy thông tin về mức độ severity, baseScore, exploitabilityScore, impactScore, cvss
    impact_data = item.get("impact", {})
    vectorString = ""
    baseScore = 0.0
    baseSeverity = ""
    exploitabilityScore = 0.0
    impactScore = 0.0
    if "baseMetricV3" in impact_data:
        bm3 = impact_data["baseMetricV3"]
        vectorString = bm3.get("cvssV3", {}).get("vectorString", "")
        baseScore = bm3.get("cvssV3", {}).get("baseScore", 0.0)
        baseSeverity = bm3.get("cvssV3", {}).get("baseSeverity", "")
        exploitabilityScore = bm3.get("exploitabilityScore", 0.0)
        impactScore = bm3.get("impactScore", 0.0)
    
    # Lấy danh sách CPE
    nodes = item.get("configurations", {}).get("nodes", [])
    cpe_info_entries = []
    for node in nodes:
        cpe_info_entries.extend(extract_child_cpe(node))
    
    # Sử dụng set để loại bỏ các CPE trùng lặp
    cpe_set = set()
    cpe_info_dict = {}
    for cpe, flat in cpe_info_entries:
        if cpe:  # chỉ xử lý nếu cpe không rỗng
            cpe_set.add(cpe)
            cpe_info_dict.setdefault(cpe, []).append(flat)
    
    cpe_list_str = ",".join(sorted(cpe_set))
    cpe_info_json = json.dumps(cpe_info_dict)
    
    return {
        "cve_id": cve_id,
        "cwe_id": cwe,
        "description": description,
        "vectorString": vectorString,
        "baseScore": baseScore,
        "baseSeverity": baseSeverity,
        "exploitabilityScore": exploitabilityScore,
        "impactScore": impactScore,
        "cpe_list": cpe_list_str,
        "cpe_info": cpe_info_json
    }

def indexing_full_cve():
    targets = list(range(2002, 2026)) + ["modified", "recent"]
    create_cve_index(targets)

def indexing_modified_recent_cve():
    targets = ["modified", "recent"]
    create_cve_index(targets)

# 3. Tạo index cho các file cve.json
def create_cve_index(targets):
    initialize_time = time.time()

    # Xử lý từng file JSON
    for target in targets:
        start_time = time.time()
        TARGET_DIR = INDEX_DIR / str(target)
        if not TARGET_DIR.exists():
            TARGET_DIR.mkdir(parents=True, exist_ok=True)
            ix = index.create_in(str(TARGET_DIR), schema)
        else:
            # Xóa các file cũ trong thư mục index
            for file in TARGET_DIR.iterdir():
                subprocess.run(["attrib", "-r", str(file)], check=True, shell=True)
                file.unlink()
            ix = index.create_in(str(TARGET_DIR), schema)
        
        # Load JSON từ file nvdcve-1.1-{target}.json
        CVE_JSON_FILE = (Path(__file__).resolve().parent / "../../src/nvd_cve_data/nvdcve-1.1-{}.json".format(target)).resolve()
        with CVE_JSON_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)

        # Lấy các CVE từ CVE_Items, sau đó parse từng CVE và thêm vào index
        with ix.writer() as writer:
            for item in tqdm(data.get("CVE_Items", []), desc=f"Index của {target}"):
                cve_info = parse_cve(item)
                writer.add_document(**cve_info)
        
        finish_time = time.time()
        print(f"Hoàn thành index cve {target} trong: {finish_time - start_time:.4f} giây")
    stop_time = time.time()
    print(f"Hoàn thành index trong: {stop_time - initialize_time:.4f} giây")
    
# 4. Tìm kiếm CVE
def search_cve(input_cpe: str, limit):
    if not INDEX_DIR.exists():
        print("whoosh_index directory not found. Please run indexing first.")
        return []
    
    # Chuẩn hóa input
    input_cpe = input_cpe.strip().lower()
    matched = []
    for year in reversed(range(2002, 2026)):
        YEAR_DIR = INDEX_DIR / str(year)
        if not YEAR_DIR.exists():
            print(f"Whoosh index directory for {year} not found. Please run indexing first.")
            continue
        ix = index.open_dir(str(YEAR_DIR))
        # Sử dụng truy vấn Term
        query = Term("cpe_list", input_cpe)
        with ix.searcher(weighting=scoring.BM25F()) as searcher:
            results = searcher.search(query, limit=limit)
            for hit in results:
                cve = hit['cve_id']
                cwe = hit['cwe_id']
                description = hit['description']
                vectorString = hit['vectorString']
                baseScore = hit['baseScore']
                baseSeverity = hit['baseSeverity']
                exploitabilityScore = hit['exploitabilityScore']
                impactScore = hit['impactScore']
                cpe_info = hit['cpe_info']
                matched.append((cve, cwe, description, vectorString ,baseScore,
                                baseSeverity, exploitabilityScore, impactScore, cpe_info))
    return matched

# 5. Tìm kiếm theo cpe chi tiết và (cpe tổng quát + check version)
def create_cve_list(input_cpe: str, input_version: str, limit):
    start = time.time()
    cpe_split = input_cpe.split(':')
    cpe_split[5] = input_version
    full_cpe = ":".join(cpe_split)

    # 5.1 Search theo cpe chi tiết
    results = search_cve(full_cpe, limit)

    # 5.2 Search theo cpe tổng quát và check dải version
    raw_results = search_cve(input_cpe, limit)
    for hit in raw_results:
        _, _, _, _, _, _, _, _, cpe_info = hit
        for ver_range in json.loads(cpe_info)[input_cpe]:
            # Kiểm tra từng ver_range
            if is_in_version_range(input_version, ver_range):
                results.append(hit)
                break
    
    # Lược cpe_info để tránh dư thừa
    final_results = []
    for result in results:
        cve, cwe, description, vectorString, baseScore, baseSeverity, exploitabilityScore, impactScore, _ = result
        final_results.append((cve, cwe, description, vectorString, baseScore, baseSeverity, exploitabilityScore, impactScore))
    end = time.time()
    print(f"Thời gian hoàn thành tìm kiếm: {end - start:.3f} giây")
    return final_results

# Check version
def is_in_version_range(cpe_version, ver_range):
    cpe_version = Version(cpe_version)
    ver_range_detail = ver_range.split('_')
    if ver_range_detail[4] == "false":
        return False
    # Dải version có dạng: verStartIncluding_verStartExcluding_verEndIncluding_verEndExcluding_isVulnerable
    if all(ver == "x" for ver in ver_range_detail[:4]):
        return False
    conditions = [
        (ver_range_detail[0], lambda v: cpe_version >= v),  # versionStartIncluding
        (ver_range_detail[1], lambda v: cpe_version > v),   # versionStartExcluding
        (ver_range_detail[2], lambda v: cpe_version <= v),  # versionEndIncluding
        (ver_range_detail[3], lambda v: cpe_version < v)    # versionEndExcluding
    ]
    for ver, check in conditions:
        if ver != "x" and not check(Version(ver)):
            return False
    return True

# Hàm đệ quy để trích xuất các đối tượng cpe_match từ một node.
def extract_child_cpe(node):
    entries = []
    if "cpe_match" in node and node["cpe_match"]:
        for match in node["cpe_match"]:
            cpe_uri = match.get("cpe23Uri", "")
            verStartIn = match.get("versionStartIncluding", "x")
            verStartEx = match.get("versionStartExcluding", "x")
            verEndIn   = match.get("versionEndIncluding", "x")
            verEndEx   = match.get("versionEndExcluding", "x")
            vuln = match.get("vulnerable")
            vuln_str = "x" if vuln is None else ("true" if vuln else "false")
            flattened = f"{verStartIn}_{verStartEx}_{verEndIn}_{verEndEx}_{vuln_str}"
            entries.append((cpe_uri, flattened))
    if "children" in node and node["children"]:
        for child in node["children"]:
            entries.extend(extract_child_cpe(child))
    return entries

def main():
    if len(sys.argv) > 1:
        print(sys.argv[1], type(sys.argv[1]))
        if sys.argv[1] == "index":
            indexing_modified_recent_cve()
            return
        elif int(sys.argv[1]) in range(2002, 2026):
            create_cve_index(["2023"])
            return


if __name__ == "__main__":
    main()
