import threading
import json
from flask import g
from flaskr import create_app
from flask import Blueprint, current_app, render_template, request, jsonify, session as ses
from flaskr.auth import login_required
from flaskr.model import URL, CVE, Tech, Tech_CVE, URL_Tech, Alerts, WAF, User
from flaskr import db, socketio
from .function.send_email import send_mail
from flaskr.function.url_monitor import check_url_status
from flaskr.function.mode_scan import manual_scan as mscan
from flaskr.function.waf_monitor import stop_monitoring_waf_for_url, monitor_waf_for_url

monitor_threads = {}  # {url_id: (thread, stop_event)}

bp = Blueprint('monitor', __name__)

@bp.route('/monitor', methods=['GET'])
@login_required
def monitoring():
    url_list = URL.query.all()
    tech_list = Tech.query.all()
    cve_list = CVE.query.all()
    waf_list = WAF.query.all()
    return render_template(
        'monitor/monitor.html',
        url_list=url_list,
        tech_list=tech_list,
        cve_list=cve_list,
        waf_list=waf_list
    )

# Khởi động thread theo dõi cho tất cả URL có monitoring_active=True
def start_watchlist_threads():
    global monitor_threads
    print("Bắt đầu monitoring")
    urls = URL.query.filter_by(monitoring_active=True).all()
    monitor_threads = {}
    for url_obj in urls:
        if url_obj.id not in monitor_threads:
            start_monitoring_for_url(url_obj.id)

@bp.route('/add_to_watchlist', methods=['POST'])
@login_required
def add_to_watchlist():
    data = request.json
    response, status_code = add_to_database(data)
    return response, status_code
    
def add_to_database(data):
    global monitor_threads
    url = data.get('url')
    url_id = add_url(url)
    try:
        for result in data.get('results'):
            # Lấy tech
            tech = result.get('tech')
            version = result.get('version')
            cpe = result.get('cpe')
            tech_id = add_tech(tech, version, cpe)
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
            
            # Lấy waf
            for waf_instance in data.get('wafs'):
                waf_manufacturer = waf_instance[0]
                waf_name = waf_instance[1]
                waf_id = add_waf(url_id, waf_name, waf_manufacturer)
        db.session.commit()
        if url_id not in monitor_threads:
            start_monitoring_for_url(url_id)
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
        stop_monitoring_for_url(url_obj.id)
        delete_url_with_association(url_obj.id)
        return "URL đã được xóa khỏi danh sách theo dõi", 200
    return "Không tìm thấy URL", 404

@bp.route('/stop_monitor/<int:url_id>', methods=['GET'])
@login_required
def stop_monitor(url_id):
    stop_monitoring_for_url(url_id)
    return jsonify(success=True)

@bp.route('/start_monitor/<int:url_id>', methods=['GET'])
@login_required
def start_monitor(url_id):
    url_obj = URL.query.get(url_id)
    user_id = ses['user_id']
    if url_obj and url_id not in monitor_threads:
        url_obj.monitoring_active = True
        db.session.commit()
        start_monitoring_for_url(url_id)
        return jsonify(success=True)
    return jsonify(success=False, message="URL đã được theo dõi hoặc không tồn tại")

# Khởi động thread theo dõi cho 1 URL cụ thể
def start_monitoring_for_url(url_id):
    url_obj = URL.query.get(url_id)
    if not url_obj:
        return
    stop_event = threading.Event()
    app = current_app._get_current_object()
    thread = threading.Thread(
        target=check_url_status,
        args=(url_obj.url, stop_event, url_obj.id, url_obj.monitoring_active),
        kwargs={'app': app},
        daemon=True
    )
    monitor_threads[url_id] = (thread, stop_event)
    thread.start()
    monitor_waf_for_url(url_id)


# Dừng thread theo dõi cho 1 URL
def stop_monitoring_for_url(url_id):
    if url_id in monitor_threads:
        thread, stop_event = monitor_threads[url_id]
        stop_event.set()
        thread.join()
        del monitor_threads[url_id]
        url_obj = URL.query.get(url_id)
        if url_obj:
            url_obj.monitoring_active = False
            db.session.commit()
        stop_monitoring_waf_for_url(url_id)


# Xử lý csdl
#####################################################################################
def add_url(url):
    existing_url = URL.query.filter_by(url=url).first()
    if existing_url:
        if not existing_url.monitoring_active:
            existing_url.monitoring_active = True
            db.session.commit()
        return existing_url.id
    new_url = URL(url=url, status="online", monitoring_active=True)
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

def add_tech(tech, version, cpe):
    existing_tech = Tech.query.filter_by(tech=tech, version=version).first()
    if existing_tech:
        return existing_tech.id
    new_tech = Tech(tech=tech, version=version, cpe=cpe)
    db.session.add(new_tech)
    db.session.flush()
    return new_tech.id

def add_alert(url_id, alert_type, title, content):
    new_alert = Alerts(url_id=url_id, alert_type=alert_type, title=title, content=content)
    db.session.add(new_alert)
    db.session.flush()
    return new_alert.id

def add_waf(url_id, waf_name, waf_manufacturer):
    existing_waf = WAF.query.filter_by(url_id=url_id, name=waf_name, manufacturer=waf_manufacturer).first()
    if existing_waf:
        return existing_waf.id
    new_waf = WAF(url_id=url_id, name=waf_name, manufacturer=waf_manufacturer)
    db.session.add(new_waf)
    db.session.flush()
    return new_waf.id

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

    # Xóa alert liên quân
    alerts = Alerts.query.filter_by(url_id=url_id).all()
    for alert in alerts:
        db.session.delete(alert)

    #  Xóa waf liên quan
    wafs = WAF.query.filter_by(url_id=url_id).all()
    print(f"Danh sách WAFs: {wafs}")
    for waf in wafs:
        print(f"Đang xóa WAF: {waf.name}")
        db.session.delete(waf)
    
    db.session.flush()

    db.session.delete(url_obj) # Xóa url cuối cùng
    db.session.commit()
#####################################################################################

# Routing tham chiếu
#####################################################################################
@bp.route('/get_cve_list/<type>/<int:id>', methods=['GET'])
@login_required
def get_cve_list(type, id):
    cve_id_list = []
    if type == 'url':
        url_techs = URL_Tech.query.filter_by(url_id=id).all()
        for url_tech in url_techs:
            tech_cves = Tech_CVE.query.filter_by(tech_id=url_tech.tech_id).all()
            for tech_cve in tech_cves:
                cve_id_list.append(tech_cve.cve_id)
    elif type == 'tech':
        tech_cves = Tech_CVE.query.filter_by(tech_id=id).all()
        for tech_cve in tech_cves:
            cve_id_list.append(tech_cve.cve_id)
    result = {
        'id': cve_id_list
    }
    return jsonify(result)

@bp.route('/get_tech_list/<type>/<int:id>', methods=['GET'])
@login_required
def get_tech_list(type, id):
    tech_id_list = []
    if type == 'url':
        url_techs = URL_Tech.query.filter_by(url_id=id).all()
        for url_tech in url_techs:
            tech_id_list.append(url_tech.tech_id)
    elif type == 'cve':
        tech_cves = Tech_CVE.query.filter_by(cve_id=id).all()
        for tech_cve in tech_cves:
            tech_id_list.append(tech_cve.tech_id)
    result = {
        'id': tech_id_list
    }
    return jsonify(result)

@bp.route('/get_url_list/<type>/<int:id>', methods=['GET'])
@login_required
def get_url_list(type, id):
    url_id_list = []
    if type == 'cve':
        tech_cves = Tech_CVE.query.filter_by(cve_id=id).all()
        for tech_cve in tech_cves:
            url_techs = URL_Tech.query.filter_by(tech_id=tech_cve.tech_id).all()
            for url_tech in url_techs:
                url_id_list.append(url_tech.url_id)
    elif type == 'tech':
        url_techs = URL_Tech.query.filter_by(tech_id=id).all()
        for url_tech in url_techs:
            url_id_list.append(url_tech.url_id)
    result = {
        'id': url_id_list
    }
    return jsonify(result)
#####################################################################################

# Quét thủ công
#####################################################################################
@bp.route('/manual-scan/<int:url_id>', methods=['GET'])
@login_required
def manual_scan(url_id):
    app = current_app._get_current_object()
    new_cves, modified_cves = mscan(url_id, app)
    if new_cves:
        title = f"Phát hiện { len(new_cves) } CVE mới!"
        alert_type = 'new'
        cve_id_list = []
        for cve, tech_id in new_cves:
            cve_name, cwe, description, vectorString, baseScore, baseSeverity, exploitabilityScore, impactScore, nucleiResult = cve
            cve_id = add_cve(cve_name, cwe, description, vectorString, baseScore, baseSeverity, exploitabilityScore, impactScore, nucleiResult)
            cve_id_list.append(cve_id)
            tech_cve_association(tech_id, cve_id)
        alert_id = add_alert(url_id=url_id, alert_type=alert_type, title=title, content=cve_id_list)
        db.session.commit()
        socketio.emit('notification_push', {
            'alert_id': alert_id,
            'url_id': url_id,
            'url': URL.query.filter_by(id=url_id).first().url,
            'alert_type': alert_type,
            'title': title,
            'content': cve_id_list 
        })
        print(title)
    
        # Gửi email khi phát hiện cve mới
        subject = title
        recipients=[user.username for user in User.query.all()]
        send_mail(
            subject=subject,
            recipients=recipients,
            template='mail/email_new_cve.html',
            title=subject,
            cves=new_cves
        )
    if modified_cves:
        title = f"Phát hiện { len(modified_cves) } CVE được chỉnh sửa!"
        change_list = []
        for info in modified_cves:
            cve, change = info
            print(change)
            cve_name = cve[0]
            change_list.append({
                "cve": cve_name,
                "changes": change
            })
            cve_instance = CVE.query.filter_by(cve=cve_name).first()
            # Update các trường thay đổi vào cơ sở dữ liệu
            for field, values in change.items():
                setattr(cve_instance, field, values['new'])
        content = json.dumps(change_list, ensure_ascii=False)
        alert_type = 'modified'
        alert_id = add_alert(url_id=url_id, alert_type=alert_type, title=title, content=content)
        db.session.commit()
        print(title)
        socketio.emit('notification_push', {
        'alert_id': alert_id,
        'url_id': url_id,
        'url': URL.query.filter_by(id=url_id).first().url,
        'alert_type': alert_type,
        'title': title,
        'content': content
        })

        # Gửi email khi phát hiện cve được chỉnh sửa
        subject = title
        recipients=[user.username for user in User.query.all()]
        send_mail(
            subject=subject,
            recipients=recipients,
            template='mail/email_modified_cve.html',
            title=subject,
            modifications=change_list
        )
    return '200', 200

@bp.route('/load_notifications', methods=['GET'])
@login_required
def load_notifications():
    alerts = Alerts.query.all()
    alerts_data = [{
        'alert_id': alert.id,
        'url_id': alert.url_id,
        'url': URL.query.get(alert.url_id).url,
        'alert_type': alert.alert_type,
        'title': alert.title,
        'content': alert.content,
        'is_read': alert.is_read
    } for alert in alerts]
    return jsonify(alerts_data)

@bp.route('/mark_alert_read/<int:alert_id>', methods=['GET'])
def set_is_read(alert_id):
    alert = Alerts.query.filter_by(id=alert_id).first()
    alert.is_read = 1
    db.session.commit()
    return '200', 200
#####################################################################################

# Quét tự động 
#####################################################################################
def auto_scan():
    try:
        from flask import current_app
        app = current_app._get_current_object()
    except RuntimeError:
        app = create_app()
    
    with app.app_context():
        # Lấy tất cả URL trong DB
        urls = URL.query.all()
        for url_obj in urls:
            print(f'Bắt đầu quét" { url_obj.url }')
            new_cves, modified_cves = mscan(url_obj.id, app)
            
            # Xử lý CVE mới
            if new_cves:
                title = f"Phát hiện {len(new_cves)} CVE mới!"
                alert_type = 'new'
                new_cve_ids = []
                for cve_info, tech_id in new_cves:
                    cve_id = add_cve(*cve_info)
                    new_cve_ids.append(cve_id)
                    tech_cve_association(tech_id, cve_id)
                alert_id = add_alert(url_obj.id, alert_type, title, new_cve_ids)
                db.session.commit()
                socketio.emit('notification_push', {
                    'alert_id': alert_id,
                    'url_id': url_obj.id,
                    'url': url_obj.url,
                    'alert_type': alert_type,
                    'title': title,
                    'content': new_cve_ids
                })
                
                # Gửi email khi phát hiện cve mới
                subject = title
                recipients=[user.username for user in User.query.all()]
                send_mail(
                    subject=subject,
                    recipients=recipients,
                    template='mail/email_new_cve.html',
                    title=subject,
                    cves=new_cves
                )
            
            # Xử lý CVE được chỉnh sửa
            if modified_cves:
                title = f"Phát hiện {len(modified_cves)} CVE được chỉnh sửa!"
                alert_type = 'modified'
                change_list = []
                for cve_info, changes in modified_cves:
                    cve_name = cve_info[0] if isinstance(cve_info, (tuple, list)) else cve_info
                    change_list.append({
                        "cve": cve_name,
                        "changes": changes
                    })
                    cve_instance = CVE.query.filter_by(cve=cve_name).first()
                    if cve_instance:
                        for field, values in changes.items():
                            setattr(cve_instance, field, values['new'])
                content = json.dumps(change_list, ensure_ascii=False)
                alert_id = add_alert(url_obj.id, alert_type, title, content)
                db.session.commit()
                socketio.emit('notification_push', {
                    'alert_id': alert_id,
                    'url_id': url_obj.id,
                    'url': url_obj.url,
                    'alert_type': alert_type,
                    'title': title,
                    'content': content
                })
                
                # Gửi email khi phát hiện cve được chỉnh sửa
                subject = title
                recipients=[user.username for user in User.query.all()]
                send_mail(
                    subject=subject,
                    recipients=recipients,
                    template='mail/email_modified_cve.html',
                    title=subject,
                    modifications=change_list
                )
        db.session.remove()
#####################################################################################
    