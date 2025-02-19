import os
import json
import time
import sys

from tqdm import tqdm
from packaging.version import Version
from whoosh import index
from whoosh.fields import Schema, TEXT, ID, STORED, KEYWORD
from whoosh.query import Term
from whoosh import scoring

# Khai báo đường dẫn đến thư mục chứa data
INDEX_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src/nvd_cve_data/whoosh_indexing"))

# 1. Tạo schema
schema = Schema(
    cve_id = ID(unique=True, stored=True),
    cwe_id = STORED,
    description = STORED,
    baseScore = STORED,
    baseSeverity = STORED,
    exploitabilityScore = STORED,
    impactScore = STORED,
    cpe_list = KEYWORD(stored=True, commas=True, lowercase=True),
    cpe_info = STORED
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
    if desc_data:
        description = desc_data[0].get("value", "")
    else:
        description = ""
    
    # Lấy thông tin về mức độ severity, baseScore, exploitabilityScore, impactScore
    impact_data = item.get("impact", {})
    baseScore = 0.0
    baseSeverity = ""
    exploitabilityScore = 0.0
    impactScore = 0.0
    
    if "baseMetricV3" in impact_data:
        bm3 = impact_data["baseMetricV3"]
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
            if cpe not in cpe_info_dict:
                cpe_info_dict[cpe] = []
            cpe_info_dict[cpe].append(flat)
    
    cpe_list_str = ",".join(sorted(cpe_set))
    cpe_info_json = json.dumps(cpe_info_dict)
    
    return {
        "cve_id": cve_id,
        "cwe_id": cwe,
        "description": description,
        "baseScore": baseScore,
        "baseSeverity": baseSeverity,
        "exploitabilityScore": exploitabilityScore,
        "impactScore": impactScore,
        "cpe_list": cpe_list_str,
        "cpe_info": cpe_info_json
    }

# 3. Tạo index cho các file cve.json
def create_cve_index():
    initialize_time = time.time()

    # Xử lý từng file JSON
    for year in range(2002, 2026):
        # Tạo thư mục chứa index, nếu đã tồn tại, refresh
        start_time = time.time()
        YEAR_DIR = INDEX_DIR + "/" + str(year)
        if not os.path.exists(YEAR_DIR):
            os.mkdir(YEAR_DIR)
            ix = index.create_in(YEAR_DIR, schema)
        else:
            for file in os.listdir(YEAR_DIR): 
                os.remove(os.path.join(YEAR_DIR, file))   
            ix = index.create_in(YEAR_DIR, schema)
        
        # Load JSON
        CVE_JSON_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src/nvd_cve_data/nvdcve-1.1-{}.json".format(year)))
        with open(CVE_JSON_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Lấy các cve từ CVE_Items, sau đó parse từng cve và xử lý
        with ix.writer() as writer:
            for item in tqdm(data.get("CVE_Items", []), desc=f"Index của năm {year}"):
                cve_info = parse_cve(item)
                writer.add_document(**cve_info)
        
        finish_time = time.time()
        print(f"Hoàn thành index cve năm { year } trong: {finish_time - start_time:.4f} giây")
    stop_time = time.time()
    print(f"Hoàn thành index trong: {stop_time - initialize_time:.4f}")
    
# 4. Tìm kiếm cve
def search_cve(input_cpe:str, limit):
    if not os.path.exists(INDEX_DIR):
        print("whoosh_index directory not found. Please run indexing first.")
        return []
    
    # Chuẩn hóa input
    input_cpe = input_cpe.strip().lower()

    matched = []
    for year in reversed(range(2002, 2026)):
        YEAR_DIR = os.path.join(INDEX_DIR, str(year))
        if not os.path.exists(YEAR_DIR):
            print(f"Whoosh index directory for {year} not found. Please run indexing first.")
            continue
        ix = index.open_dir(YEAR_DIR)

        # Sử dụng truy vấn Term (hoặc Wildcard nếu cần)
        query = Term("cpe_list", input_cpe)

        with ix.searcher(weighting=scoring.BM25F()) as searcher:
            results = searcher.search(query, limit=limit)
            for hit in results:
                cve = hit['cve_id']
                cwe = hit['cwe_id']
                description = hit['description']
                baseScore = hit['baseScore']
                baseSeverity = hit['baseSeverity']
                exploitabilityScore = hit['exploitabilityScore']
                impactScore = hit['impactScore']
                cpe_list = hit['cpe_list']
                cpe_info = hit['cpe_info']
                # Vẫn cần trả về cpe_info, cpe_list thì không cần nữa vì chỉ cần search ban đầu 
                matched.append((cve, cwe, description, baseScore, baseSeverity, 
                                exploitabilityScore, impactScore, cpe_info))
    return(matched)

# 5. Tìm kiếm theo cpe chi tiết và (cpe tổng quát + check version)
def create_cve_list(input_cpe:str, input_version:str, limit):
    start = time.time()
    cpe_split = input_cpe.split(':')
    cpe_split[5] = input_version
    full_cpe = ":".join(cpe_split)

    # 5.1 Search theo cpe chi tiết
    results = search_cve(full_cpe, limit)

    # 5.2 Search theo cpe tổng quát và check dải version
    raw_results = search_cve(input_cpe, limit)
    for hit in raw_results:
        _, _, _, _, _, _, _, cpe_info = hit
        for ver_range in json.loads(cpe_info)[input_cpe]:
            # gọi hàm check từng ver_range
            if is_in_version_range(input_version, ver_range):
                results.append(hit)
                break
    
    # Lược cpe_info để tránh dư thừa
    final_results = []
    for result in results:
        cve, cwe, description, baseScore, baseSeverity, exploitabilityScore, impactScore, _ = result
        final_results.append((cve, cwe, description, baseScore, baseSeverity, exploitabilityScore, impactScore))
    end = time.time()
    print(f"Thời gian hoàn thành tìm kiếm: {end-start:.3f}")

    return(final_results)


# Check version
def is_in_version_range(cpe_version, ver_range):
    cpe_version = Version(cpe_version)
    ver_range_detail = ver_range.split('_')

    if ver_range_detail[4] == "false":
        return False
    
    # dải version có dạng: verStartIncluding_verStartExcluding_verEndIncluding_verEndExcluding_isVulnerable
    # Xử lý các trường hợp cve chi tiết chính là cve tổng quát để tránh trùng lặp
    if all(ver == "x" for ver in ver_range_detail[:4]):
        return False
    
    conditions = [
        (ver_range_detail[0], lambda v: cpe_version >= v),  # versionStartIncluding
        (ver_range_detail[1], lambda v: cpe_version > v),   # versionStartExcluding
        (ver_range_detail[2], lambda v: cpe_version <= v),  # versionEndIncluding
        (ver_range_detail[3], lambda v: cpe_version < v)    # versionEndExcluding
    ]
    
    # Kiểm tra từng điều kiện
    for ver, check in conditions:
        if ver != "x" and not check(Version(ver)):
            return False
    return True


# Hàm đệ quy để trích xuất các đối tượng cpe_match từ một node.
# Mỗi đối tượng sẽ được chuyển thành một tuple (cpe23Uri, flattened_string)
# với flattened_string có định dạng:
#    verStartIn_verStartEx_verEndIn_verEndEx_vulnerable
# Nếu trường nào không có thì thay bằng "x" (ví dụ: x_x_x_x_true).
def extract_child_cpe(node):
    entries = []
    
    # Nếu có trường "cpe_match" trong node, xử lý các phần tử bên trong
    if "cpe_match" in node and node["cpe_match"]:
        for match in node["cpe_match"]:
            cpe_uri = match.get("cpe23Uri", "")
            # Lấy các trường version; nếu không có, thay bằng "x"
            verStartIn = match.get("versionStartIncluding", "x")
            verStartEx = match.get("versionStartExcluding", "x")
            verEndIn   = match.get("versionEndIncluding", "x")
            verEndEx   = match.get("versionEndExcluding", "x")
            # Lấy trường vulnerable: chuyển thành "true" hoặc "false"; nếu không có thì "x"
            vuln = match.get("vulnerable")
            if vuln is None:
                vuln_str = "x"
            else:
                vuln_str = "true" if vuln else "false"
            
            flattened = f"{verStartIn}_{verStartEx}_{verEndIn}_{verEndEx}_{vuln_str}"
            entries.append((cpe_uri, flattened))
    
    # Nếu có trường "children", đệ quy qua các node con
    if "children" in node and node["children"]:
        for child in node["children"]:
            entries.extend(extract_child_cpe(child))
    
    return entries

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "index":
        create_cve_index()
        return
    input_cpe = input("Nhập CPE: ")
    input_version = input("Nhập version: ")
    create_cve_list(input_cpe, input_version, 100)

if __name__ == "__main__":
    main()

