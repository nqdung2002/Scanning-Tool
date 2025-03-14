from flaskr.model import URL, CVE, Tech, Tech_CVE, URL_Tech, Alerts
from flaskr import db, create_app, socketio
from flaskr.function.cve_scan import create_cve_list
from flaskr.scan import nuclei_scan

def manual_scan(url_id, app):
    manual_cve_scan = []
    cve_name_list = []
    nuclei_cve_name_target = []

    # Lấy url và thông tin liên quan
    with app.app_context():
        url_obj = URL.query.filter_by(id=url_id).first()
        if not url_obj:
            print(f"URL với id {url_id} không tồn tại.")
            return

        url = url_obj.url
        url_techs = URL_Tech.query.filter_by(url_id=url_id).all()
        for url_tech in url_techs:
            tech = Tech.query.filter_by(id=url_tech.tech_id).first()
            cpe = tech.cpe
            version = tech.version
            results = create_cve_list(cpe, version, 100) # Tìm cve từ danh sách các năm (dành cho thủ công)
            for result in results:
                manual_cve_scan.append(result) # Đã lấy được kết quả quét thủ công
                cve_name_list.append((result[0], url_tech.tech_id))
                nuclei_cve_name_target.append(result[0])

    # nuclei 
    nuclei_results = nuclei_scan(nuclei_cve_name_target, url)

    new_cves = []
    modified_cves = []
    for cve, tech_id in cve_name_list:
        cve_name = cve
        new_nuclei_result = nuclei_results[cve_name].get('status')
        new_base_score = manual_cve_scan[cve_name_list.index((cve_name, tech_id))][4]
        new_severity = manual_cve_scan[cve_name_list.index((cve_name, tech_id))][5]
        is_new, is_diff, changes = is_different(cve_name, new_nuclei_result, new_base_score, new_severity, app)
        if is_new: 
            # Thêm nuclei_result vào cuối mỗi tuple CVE
            cve = manual_cve_scan[cve_name_list.index((cve_name, tech_id))] + (new_nuclei_result,)
            new_cves.append((cve, tech_id))
        elif is_diff:
            modified_cves.append((manual_cve_scan[cve_name_list.index((cve_name, tech_id))], changes))
    return new_cves, modified_cves

def is_different(cve_name, new_nuclei_result, new_base_score, new_severity, app):
    with app.app_context():
        cve = CVE.query.filter_by(cve=cve_name).first()
        if not cve:
            return True, False, None

        changes = {}
        if cve.nucleiResult != new_nuclei_result:
            changes["nucleiResult"] = {"old": cve.nucleiResult, "new": new_nuclei_result}
        if cve.baseScore != new_base_score:
            changes["baseScore"] = {"old": cve.baseScore, "new": new_base_score}
        if cve.baseSeverity != new_severity:
            changes["baseSeverity"] = {"old": cve.baseSeverity, "new": new_severity}

        if changes:
            return False, True, changes
        else:
            return False, False, None
    