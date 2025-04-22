from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER
import io
from flask import Blueprint, request, send_file
from flaskr.model import URL, CVE, Tech_CVE, URL_Tech, Alerts, WAF, Tech
from datetime import datetime,timedelta

bp = Blueprint('export', __name__)

@bp.route('/export', methods=['POST'])
def export_pdf():
    pdfmetrics.registerFont(TTFont('Roboto', 'flaskr/static/fonts/Roboto/Roboto-VariableFont_wdth,wght.ttf'))

    # Lấy dữ liệu từ form
    selected_urls = []
    story = []
    mode = request.form.get('mode')
    report_name = None

    # Tạo file PDF và set style
    pdf_output = io.BytesIO()
    doc = SimpleDocTemplate(pdf_output, pagesize=A4)
    styles = getSampleStyleSheet()
    style_normal = styles["Normal"]
    style_normal.fontName = "Roboto"
    style_normal.fontSize = 14
    style_heading = styles["Heading1"]
    style_heading.fontName = "Roboto"
    style_heading.fontSize = 18
    style_heading.textColor = HexColor("#2E86C1")
    style_heading.alignment = TA_CENTER
    style_heading.spaceAfter = 20
    total_severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    table_paragraph_style = ParagraphStyle(
        name="TableParagraph",
        fontName="Roboto",
        fontSize=12,
        leading=14,  # Khoảng cách giữa các dòng
        alignment=0  # Căn trái
    )

    # Xuất báo cáo tổng hợp CVE
    if mode == '1':
        selected_urls = request.form.getlist('urls')
        report_name = 'report_cves.pdf'
        story.append(Paragraph("<b>BÁO CÁO TỔNG HỢP LỖ HỔNG BẢO MẬT</b>", style_heading))
        story.append(Spacer(1, 12))

        if selected_urls:
            for url in selected_urls:
                # Bảng tên domain
                table_heading = Table([['Domain', url]], colWidths=[100, 360])
                table_heading.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), HexColor("#5c67fa")),
                    ('TEXTCOLOR', (0, 0), (0, 0), colors.whitesmoke),
                    ('FONTNAME', (0, 0), (-1, -1), 'Roboto'),
                    ('FONTSIZE', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT')
                ]))
                story.append(table_heading)
                story.append(Spacer(1, 12))

                url_obj = URL.query.filter_by(url=url).first()
                if url_obj:
                    url_techs = URL_Tech.query.filter_by(url_id=url_obj.id).all()
                    techs = []
                    cves = []
                    severity_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
                    for url_tech in url_techs:
                        # Tạo bảng tech
                        tech_objs = Tech.query.filter_by(id=url_tech.tech_id).all()
                        for tech_obj in tech_objs:
                            techs.append({
                                'tech': tech_obj.tech,
                                'version': tech_obj.version,
                                'cpe': tech_obj.cpe
                            })
                        # Tìm CVE theo Tech
                        tech_cves = Tech_CVE.query.filter_by(tech_id=url_tech.tech_id).all()
                        for tech_cve in tech_cves:
                            cve = CVE.query.get(tech_cve.cve_id)
                            if cve:
                                severity = cve.baseSeverity or "Unknown"
                                if severity in severity_count:
                                    severity_count[severity] += 1
                                    total_severity_count[severity] += 1
                                cves.append({
                                    "cve": cve.cve,
                                    "severity": cve.baseSeverity,
                                    "base_score": cve.baseScore,
                                    "updated_at": cve.updated_at.strftime("%Y-%m-%d") if cve.updated_at else "N/A"
                                })

                    table_tech_data = [["Technologies", "Version", "CPE"]]
                    for item in techs:
                        table_tech_data.append([item['tech'], item['version'], item['cpe']])
                    table_tech = Table(table_tech_data, colWidths=[80, 60, 320])
                    table_tech.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('FONTNAME', (0, 0), (-1, -1), 'Roboto'),
                        ('FONTSIZE', (0, 0), (-1, -1), 10),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT')
                    ]))
                    story.append(table_tech)
                    story.append(Spacer(1, 12))

                    table_data = [["CVE ID", "Severity", "Base Score", "Updated At"]]
                    for item in cves:
                        table_data.append([item["cve"], item["severity"], str(item["base_score"]), item["updated_at"]])

                    table = Table(table_data, colWidths=[165, 95, 90, 110])
                    table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('FONTNAME', (0, 0), (-1, -1), 'Roboto'),
                        ('FONTSIZE', (0, 0), (-1, -1), 12),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT')
                    ]))

                    story.append(table)
                    story.append(Spacer(1, 12))

                    story.append(Paragraph("<b>Tổng số CVE theo mức độ:</b>", style_normal))
                    story.append(Spacer(1, 12))
                    for sev, count in severity_count.items():
                        story.append(Paragraph(f"{sev}: {count}", style_normal))
                        story.append(Spacer(1, 12))
                    story.append(PageBreak())

        story.append(Paragraph("<b>Tổng hợp tất cả CVE theo mức độ:</b>", style_heading))
        for sev, count in total_severity_count.items():
            story.append(Paragraph(f"{sev}: {count}", style_normal))
            story.append(Spacer(1, 12))

    elif mode == '2':
        selected_urls = request.form.getlist('urlWithTime')
        report_name = 'report_alerts.pdf'
        start_date = request.form.get('startDate')
        end_date = request.form.get('endDate')

        # Chuyển đổi start_date và end_date sang định dạng datetime
        
        start_date = datetime.strptime(start_date, "%Y-%m-%d")
        end_date = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1) - timedelta(seconds=1)

        story.append(Paragraph("<b>BÁO CÁO CÁC ALERTS TRONG KHOẢNG THỜI GIAN</b>", style_heading))
        story.append(Spacer(1, 12))

        if selected_urls:
            for url in selected_urls:
                # Bảng tên domain
                table_heading_data = [['Domain', url],
                                      ['Start date', start_date],
                                      ['End date', end_date]]
                table_head = Table(table_heading_data, colWidths=[100, 360])
                table_head.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), HexColor("#5c67fa")),
                    ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
                    ('FONTNAME', (0, 0), (-1, -1), 'Roboto'),
                    ('FONTSIZE', (0, 0), (-1, -1), 12),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT')
                ]))
                story.append(table_head)
                story.append(Spacer(1, 12))

                # Truy vấn các alerts liên quan đến URL trong khoảng thời gian
                url_obj = URL.query.filter_by(url=url).first()
                if url_obj:
                    alerts = Alerts.query.filter(
                        Alerts.url_id == url_obj.id,
                        Alerts.notified_at >= start_date,
                        Alerts.notified_at <= end_date
                    ).all()

                    if alerts:
                        table_data = [["Alert ID", "Alert Type", "Title", "Notified At"]]
                        for alert in alerts:
                            table_data.append([
                                alert.id,
                                alert.alert_type,
                                Paragraph(alert.title, table_paragraph_style),
                                alert.notified_at.strftime("%d-%m-%Y %H:%M:%S")
                            ])

                        table = Table(table_data, colWidths=[60, 100, 150, 150])
                        table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                            ('FONTNAME', (0, 0), (-1, -1), 'Roboto'),
                            ('FONTSIZE', (0, 0), (-1, -1), 12),
                            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT')
                        ]))

                        story.append(table)
                        story.append(Spacer(1, 12))
                    else:
                        story.append(Paragraph("<i>Không có alert nào trong khoảng thời gian này.</i>", style_normal))
                        story.append(Spacer(1, 12))
                else:
                    story.append(Paragraph("<i>URL không tồn tại trong cơ sở dữ liệu.</i>", style_normal))
                    story.append(Spacer(1, 12))

                story.append(PageBreak())
        else:
            story.append(Paragraph("<i>Không có URL nào được chọn.</i>", style_normal))
            story.append(Spacer(1, 12))

    doc.build(story)
    pdf_output.seek(0)

    return send_file(pdf_output, as_attachment=True, download_name=report_name, mimetype='application/pdf')
