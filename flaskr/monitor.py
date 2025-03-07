from flask import Blueprint, flash, render_template, request, jsonify
from flaskr.auth import login_required
from flaskr.model import URL, CVE, Tech, Tech_CVE, URL_Tech
from flaskr import db


bp = Blueprint('monitor', __name__)

@bp.route('/monitor', methods=['GET'])
@login_required
def monitoring():
    url_list = URL.query.all()
    tech_list = Tech.query.all()
    cve_list = CVE.query.all()
    url_tech_list = URL_Tech.query.all()
    tech_cve_list = Tech_CVE.query.all()
    return render_template(
        'monitor/monitor.html',
        url_list=url_list,
        tech_list=tech_list,
        cve_list=cve_list,
        url_tech_list=url_tech_list,
        tech_cve_list=tech_cve_list
    )

@bp.route('/add_to_watchlist', methods=['POST'])
@login_required
def add_to_watchlist():
    data = request.json
    url = data.get('url')
    url_id = add_url(url)
    print(url_id)
    try:
        for result in data.get('results'):
            # Lấy tech
            tech = result.get('tech')
            version = result.get('version')
            tech_id = add_tech(tech, version)
            url_tech_association(url_id, tech_id)

            # Lấy từng CVE
            for cve_instance in result.get('cves'):
                cve = cve_instance.get("cve")
                cwe = cve_instance.get("cwe")
                description = cve_instance.get("description")
                vectorString = cve_instance.get("vectorString")
                baseScore = cve_instance.get("baseScore")
                baseSeverity = cve_instance.get("baseSeverity")
                exploitabilityScore = cve_instance.get("exploitabilityScore")
                impactScore = cve_instance.get("impactScore")
                nucleiResult = cve_instance.get("nucleiResult")
                cve_id = add_cve(cve, cwe, description, vectorString, baseScore, baseSeverity, exploitabilityScore, impactScore, nucleiResult)
                tech_cve_association(tech_id, cve_id)
        db.session.commit()
        return "Thành công!!!", 200
    except Exception as e:
        db.session.rollback()
        print(f"lỗi ồiiii: {e}")
        return "Lỗi òi", 500
    
@bp.route('/remove_from_watchlist', methods=['POST'])
@login_required
def remove_from_watchlist():
    data = request.get_data(as_text=True)
    url_obj = URL.query.filter_by(url=data).first()
    if url_obj:
        delete_url_with_association(url_obj.id)
        return "URL đã được xóa khỏi danh sách theo dõi", 200
    return "Không tìm thấy URL", 404


# Xử lý csdl
#####################################################################################
def add_url(url):
    existing_url = URL.query.filter_by(url=url).first()
    if existing_url:
        return existing_url.id
    new_url = URL(url=url, status="online")
    db.session.add(new_url)
    db.session.flush()
    return new_url.id

def add_cve(cve, cwe, description, vectorString, baseScore, baseSeverity, exploitabilityScore, impactScore, nucleiResult):
    existing_cve = CVE.query.filter_by(cve=cve).first()
    if existing_cve:
        return existing_cve.id
    new_cve = CVE(
        cve = cve,
        cwe = cwe,
        description = description,
        vectorString = vectorString,
        baseScore = baseScore,
        baseSeverity = baseSeverity,
        exploitabilityScore = exploitabilityScore,
        impactScore = impactScore,
        nucleiResult = nucleiResult
    )
    db.session.add(new_cve)
    db.session.flush()
    return new_cve.id

def add_tech(tech, version):
    existing_tech = Tech.query.filter_by(tech=tech, version=version).first()
    if existing_tech:
        return existing_tech.id
    new_tech = Tech(tech=tech, version=version)
    db.session.add(new_tech)
    db.session.flush()
    return new_tech.id

def url_tech_association(url_id, tech_id):
    if not URL_Tech.query.filter_by(url_id=url_id, tech_id=tech_id).first():
        association = URL_Tech(url_id=url_id, tech_id=tech_id)
        db.session.add(association)
        db.session.flush()

def tech_cve_association(tech_id, cve_id):
    if not Tech_CVE.query.filter_by(tech_id=tech_id, cve_id=cve_id).first():
        association = Tech_CVE(tech_id=tech_id, cve_id=cve_id)
        db.session.add(association)
        db.session.flush()

def delete_url_with_association(url_id):
    url_obj = URL.query.get(url_id)
    if not url_obj:
        print("URL không tồn tại.")
        return

    # Kiểm tra xem còn association nào giữa url bị xóa và các tech không
    url_tech_assocciations = URL_Tech.query.filter_by(url_id=url_id).all()
    for ut_association in url_tech_assocciations:
        tech_id = ut_association.tech_id
        db.session.delete(ut_association) # Xóa association sau khi lấy được các tech_id gắn với nó
        other_association_count = URL_Tech.query.filter_by(tech_id=tech_id).count()

        # Nếu xem tech còn association với url nào khác không, nếu còn thì bỏ qua
        if other_association_count == 0:
            tech_obj = Tech.query.get(tech_id)
            tech_cve_associations = Tech_CVE.query.filter_by(tech_id=tech_id).all()

            #Kiểm tra xem tech còn association với cve nào nữa không
            for tc_association in tech_cve_associations:
                cve_id = tc_association.cve_id
                db.session.delete(tc_association) # xóa association sau khi lấy cac cve_id liên quan
                cve_other_association_count = Tech_CVE.query.filter_by(cve_id=cve_id).count()

                # Kiểm tra số lượng association còn lại của cve, nếu còn thì bỏ qua, nếu không thì xóa
                if cve_other_association_count == 0:
                    cve_obj = CVE.query.get(cve_id)
                    if cve_obj:
                        db.session.delete(cve_obj) # Xóa cve
            if tech_obj:
                db.session.delete(tech_obj) # Xóa tech
    db.session.delete(url_obj) # Xóa url cuối cùng
    db.session.commit()





    

    