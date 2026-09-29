from flask import Flask, render_template, request, jsonify, send_file
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from analyzer import analyze_email_text, parse_eml
from pathlib import Path
from datetime import datetime
from uuid import uuid4
import json

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
last_result = None
REPORTS_DIR = Path(__file__).parent / 'reports'
REPORTS_FILE = REPORTS_DIR / 'saved_reports.json'
REPORTS_DIR.mkdir(exist_ok=True)

def load_saved_reports():
    if not REPORTS_FILE.exists():
        return []
    try:
        return json.loads(REPORTS_FILE.read_text(encoding='utf-8'))
    except (json.JSONDecodeError, OSError):
        return []

def write_saved_reports(reports):
    REPORTS_FILE.write_text(json.dumps(reports, indent=2, ensure_ascii=False), encoding='utf-8')

def make_pdf(result):
    stream = BytesIO(); pdf = canvas.Canvas(stream, pagesize=A4); width, height = A4
    y = height - 55
    pdf.setTitle('Phishing Investigation Report')
    pdf.setFont('Helvetica-Bold', 18); pdf.drawString(45, y, 'Phishing Investigation Report'); y -= 34
    pdf.setFont('Helvetica', 11)
    rows = [('Subject',result.get('subject','')),('Sender',result.get('sender','')),('Reply-To',result.get('reply_to','')),('Risk',f"{result.get('risk','Unknown')} ({result.get('score',0)}/100)")]
    for label, value in rows:
        pdf.setFont('Helvetica-Bold',10); pdf.drawString(45,y,label+':'); pdf.setFont('Helvetica',10); pdf.drawString(120,y,str(value)[:85]); y-=20
    y-=8; pdf.setFont('Helvetica-Bold',12); pdf.drawString(45,y,'Evidence'); y-=20
    for item in result.get('evidence', []):
        text = f"- {item.get('title','Indicator')}: {item.get('detail','')}"
        for chunk in [text[i:i+92] for i in range(0,len(text),92)]:
            pdf.setFont('Helvetica',9); pdf.drawString(50,y,chunk); y-=14
            if y < 70: pdf.showPage(); y=height-55
    y-=8; pdf.setFont('Helvetica-Bold',12); pdf.drawString(45,y,'Safety recommendation'); y-=18
    pdf.setFont('Helvetica',9)
    rec=result.get('recommendation','')
    for chunk in [rec[i:i+92] for i in range(0,len(rec),92)]: pdf.drawString(50,y,chunk); y-=14
    pdf.save(); stream.seek(0)
    return stream

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    global last_result
    try:
        uploaded = request.files.get('email_file')
        pasted = request.form.get('email_text', '').strip()
        if uploaded and uploaded.filename:
            if not uploaded.filename.lower().endswith('.eml'):
                return jsonify({'error':'Please upload a valid .eml file.'}), 400
            last_result = parse_eml(uploaded.read(), uploaded.filename)
        elif pasted:
            last_result = analyze_email_text(pasted)
        else:
            return jsonify({'error':'Upload a .eml file or paste an email first.'}), 400
        return jsonify(last_result)
    except Exception as error:
        print('Email analysis failed:', error)
        return jsonify({'error':'Unable to analyze this email. Please check the supplied content.'}), 500

@app.route('/report')
def report():
    if not last_result:
        return 'Analyze an email first.', 400
    return send_file(make_pdf(last_result), mimetype='application/pdf', as_attachment=True, download_name='phishing-investigation-report.pdf')

@app.route('/reports', methods=['GET'])
def recent_reports():
    reports = load_saved_reports()
    summaries = [{
        'id': item['id'], 'saved_at': item['saved_at'],
        'subject': item['result'].get('subject') or 'Untitled email',
        'sender': item['result'].get('sender') or 'Unknown sender',
        'risk': item['result'].get('risk') or 'Unknown',
        'score': item['result'].get('score', 0)
    } for item in reports]
    return jsonify(summaries)

@app.route('/reports/save', methods=['POST'])
def save_report():
    if not last_result:
        return jsonify({'error': 'Analyze an email first.'}), 400
    reports = load_saved_reports()
    entry = {
        'id': uuid4().hex[:10],
        'saved_at': datetime.now().astimezone().isoformat(timespec='seconds'),
        'result': last_result
    }
    reports.insert(0, entry)
    reports = reports[:30]
    write_saved_reports(reports)
    return jsonify({'message': 'Report saved.', 'id': entry['id'], 'saved_at': entry['saved_at']})

@app.route('/reports/<report_id>/download')
def download_saved_report(report_id):
    entry = next((x for x in load_saved_reports() if x.get('id') == report_id), None)
    if not entry:
        return 'Saved report not found.', 404
    filename = f"phishy-report-{report_id}.pdf"
    return send_file(make_pdf(entry['result']), mimetype='application/pdf', as_attachment=True, download_name=filename)

@app.route('/reports/<report_id>', methods=['DELETE'])
def delete_saved_report(report_id):
    reports = load_saved_reports()
    kept = [x for x in reports if x.get('id') != report_id]
    if len(kept) == len(reports):
        return jsonify({'error': 'Saved report not found.'}), 404
    write_saved_reports(kept)
    return jsonify({'message': 'Report deleted.'})

if __name__ == '__main__':
    app.run(debug=True)
