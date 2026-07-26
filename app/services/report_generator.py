import os
import csv
from datetime import datetime
from app import db
from app.models.alert import Alert
from app.models.report import Report as ReportModel

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

class ReportGenerator:
    @staticmethod
    def generate_csv_report(filepath, alerts):
        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['Alert ID', 'Timestamp', 'Source IP', 'Destination IP', 'Attack Type', 'Severity', 'Confidence Score', 'Status']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for alert in alerts:
                    writer.writerow({
                        'Alert ID': alert.id,
                        'Timestamp': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                        'Source IP': alert.src_ip,
                        'Destination IP': alert.dst_ip,
                        'Attack Type': alert.attack_type,
                        'Severity': alert.severity,
                        'Confidence Score': f"{alert.confidence:.4f}",
                        'Status': alert.status
                    })
            return True
        except Exception as e:
            print(f"Error generating CSV report: {e}")
            return False

    @staticmethod
    def generate_pdf_report(filepath, analyst_name):
        try:
            total_alerts = Alert.query.count()
            active_alerts = Alert.query.filter_by(status='Active').count()
            resolved_alerts = Alert.query.filter_by(status='Resolved').count()
            
            low_count = Alert.query.filter_by(severity='Low').count()
            med_count = Alert.query.filter_by(severity='Medium').count()
            high_count = Alert.query.filter_by(severity='High').count()
            crit_count = Alert.query.filter_by(severity='Critical').count()
            
            attack_types_query = db.session.query(Alert.attack_type, db.func.count(Alert.id)).group_by(Alert.attack_type).all()
            attack_types = sorted(attack_types_query, key=lambda x: x[1], reverse=True)[:5]
            
            source_ips_query = db.session.query(Alert.src_ip, db.func.count(Alert.id)).group_by(Alert.src_ip).all()
            source_ips = sorted(source_ips_query, key=lambda x: x[1], reverse=True)[:5]
            
            recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()
            
            doc = SimpleDocTemplate(filepath, pagesize=letter, rightMargin=54, leftMargin=54, topMargin=54, bottomMargin=54)
            styles = getSampleStyleSheet()
            
            theme_color = colors.HexColor('#1e293b')
            accent_color = colors.HexColor('#0284c7')
            
            title_style = ParagraphStyle(
                'DocTitle',
                parent=styles['Heading1'],
                fontName='Helvetica-Bold',
                fontSize=24,
                textColor=theme_color,
                spaceAfter=15
            )
            
            h2_style = ParagraphStyle(
                'SectionHeader',
                parent=styles['Heading2'],
                fontName='Helvetica-Bold',
                fontSize=14,
                textColor=accent_color,
                spaceBefore=15,
                spaceAfter=10,
                keepWithNext=True
            )
            
            body_style = ParagraphStyle(
                'BodyTextCustom',
                parent=styles['BodyText'],
                fontName='Helvetica',
                fontSize=10,
                textColor=colors.HexColor('#334155'),
                spaceAfter=8
            )
            
            bold_body_style = ParagraphStyle(
                'BodyTextBoldCustom',
                parent=body_style,
                fontName='Helvetica-Bold'
            )
            
            story = []
            
            story.append(Paragraph("AI-NIDS SECURITY COMPLIANCE REPORT", title_style))
            story.append(Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", body_style))
            story.append(Paragraph(f"Security Analyst: {analyst_name}", body_style))
            story.append(Spacer(1, 10))
            
            divider = Table([['']], colWidths=[500], rowHeights=[3])
            divider.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), accent_color),
                ('TOPPADDING', (0,0), (-1,-1), 0),
                ('BOTTOMPADDING', (0,0), (-1,-1), 0),
            ]))
            story.append(divider)
            story.append(Spacer(1, 15))
            
            story.append(Paragraph("1. Executive Summary", h2_style))
            summary_text = (
                "This document is an automated security audit generated by the AI-Integrated Network Intrusion Detection "
                "System (AI-NIDS). It encapsulates active network alerts, heuristic rules classification violations, "
                "and anomalies identified by the machine learning engine. This report aims to support security operations "
                "analysts in prioritizing patch tasks, firewall configurations, and forensic analysis."
            )
            story.append(Paragraph(summary_text, body_style))
            
            stats_data = [
                [Paragraph("<b>Metric</b>", bold_body_style), Paragraph("<b>Count</b>", bold_body_style), Paragraph("<b>Status</b>", bold_body_style), Paragraph("<b>Breakdown</b>", bold_body_style)],
                ["Total Alerts Logged", str(total_alerts), "Active Cases", f"Low: {low_count}"],
                ["Active Threats", str(active_alerts), "Mitigated", f"Medium: {med_count}"],
                ["Resolved Incidents", str(resolved_alerts), "Efficiency: {:.1f}%".format(resolved_alerts/total_alerts*100 if total_alerts > 0 else 100), f"High: {high_count}"],
                ["Critical Anomalies", str(crit_count), "", f"Critical: {crit_count}"]
            ]
            
            stats_table = Table(stats_data, colWidths=[150, 80, 120, 150])
            stats_table.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cbd5e1')),
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f1f5f9')),
                ('PADDING', (0,0), (-1,-1), 6),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            story.append(stats_table)
            story.append(Spacer(1, 20))
            
            story.append(Paragraph("2. Threat Analysis Summary", h2_style))
            analysis_text = "The table below outlines the primary intrusion vectors and the leading offensive IP coordinates:"
            story.append(Paragraph(analysis_text, body_style))
            
            att_rows = [[Paragraph("<b>Attack Classification</b>", bold_body_style), Paragraph("<b>Frequency</b>", bold_body_style)]]
            for name, cnt in attack_types:
                att_rows.append([name, str(cnt)])
            if len(attack_types) == 0:
                att_rows.append(["No alerts logged", "0"])
            
            ip_rows = [[Paragraph("<b>Source IP Actor</b>", bold_body_style), Paragraph("<b>Incidents Triggered</b>", bold_body_style)]]
            for ip, cnt in source_ips:
                ip_rows.append([ip, str(cnt)])
            if len(source_ips) == 0:
                ip_rows.append(["No threat IPs recorded", "0"])
                
            sub_table_data = [
                [Table(att_rows, colWidths=[160, 60]), Table(ip_rows, colWidths=[160, 70])]
            ]
            sub_table = Table(sub_table_data, colWidths=[240, 260])
            sub_table.setStyle(TableStyle([
                ('VALIGN', (0,0), (-1,-1), 'TOP'),
                ('LEFTPADDING', (0,0), (-1,-1), 0),
                ('RIGHTPADDING', (0,0), (-1,-1), 0),
            ]))
            story.append(sub_table)
            story.append(Spacer(1, 20))
            
            story.append(Paragraph("3. Log of Recent Security Alerts", h2_style))
            
            log_data = [[
                Paragraph("<b>ID</b>", bold_body_style), 
                Paragraph("<b>Timestamp</b>", bold_body_style), 
                Paragraph("<b>Source IP</b>", bold_body_style), 
                Paragraph("<b>Attack Type</b>", bold_body_style), 
                Paragraph("<b>Sev</b>", bold_body_style), 
                Paragraph("<b>Conf</b>", bold_body_style)
            ]]
            
            for al in recent_alerts:
                log_data.append([
                    str(al.id),
                    al.timestamp.strftime('%H:%M:%S'),
                    al.src_ip,
                    al.attack_type,
                    al.severity,
                    f"{al.confidence:.2f}"
                ])
                
            if len(recent_alerts) == 0:
                log_data.append(["-", "No recent alerts", "-", "-", "-", "-"])
                
            log_table = Table(log_data, colWidths=[30, 70, 110, 160, 80, 50])
            log_table.setStyle(TableStyle([
                ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f8fafc')),
                ('PADDING', (0,0), (-1,-1), 5),
                ('FONTSIZE', (0,0), (-1,-1), 8),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ]))
            story.append(log_table)
            story.append(Spacer(1, 20))
            
            story.append(Paragraph("4. Recommended Mitigations & Security Posture", h2_style))
            
            recs = []
            if crit_count > 0 or high_count > 0:
                recs.append("<b>[IMMEDIATE] Firewalls Rules Update:</b> Add block rules targeting the top offending source IPs identified in Section 2.")
                recs.append("<b>[IMMEDIATE] DoS Mitigation:</b> Activate SYN cookies and limit connections rates on edge reverse proxies/load balancers to suppress DoS alerts.")
            if med_count > 0:
                recs.append("<b>[ACTION REQUIRED] Vulnerability Patching:</b> Examine target ports on systems receiving Port Scan probes. Close idle public ports.")
                recs.append("<b>[ACTION REQUIRED] Credential Policies:</b> Update brute-forced protocols (SSH, FTP, RDP) to require SSH keys and configure fail2ban limits.")
            recs.append("<b>[BEST PRACTICE] AI Re-training:</b> Periodically re-train the Random Forest classifier with newly identified traffic logs to prevent false-positive drift.")
            
            for idx, rec in enumerate(recs):
                story.append(Paragraph(f"{idx+1}. {rec}", body_style))
                
            doc.build(story)
            return True
        except Exception as e:
            print(f"Error compiling PDF report: {e}")
            return False
