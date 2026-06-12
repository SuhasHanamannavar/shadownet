import os
import sqlite3
import openai
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

import config

client = openai.OpenAI(api_key=config.OPENAI_API_KEY)

def get_session_data(session_id):
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,))
    session = c.fetchone()
    
    c.execute("SELECT command FROM commands WHERE session_id=?", (session_id,))
    commands = [row['command'] for row in c.fetchall()]
    conn.close()
    
    if session:
        session = dict(session)
        session['commands'] = commands
    return session

def generate_report(session_id):
    """
    generate_report(session_id) -> creates PDF using ReportLab
    Returns the path to the PDF.
    """
    try:
        session = get_session_data(session_id)
        if not session:
            return None
            
        reports_dir = "./data/reports"
        os.makedirs(reports_dir, exist_ok=True)
        pdf_path = os.path.join(reports_dir, f"session_{session_id}.pdf")
        
        doc = SimpleDocTemplate(pdf_path, pagesize=letter)
        styles = getSampleStyleSheet()
        Story = []
        
        Story.append(Paragraph(f"Attacker Profile Report: {session_id}", styles['Title']))
        Story.append(Spacer(1, 12))
        
        Story.append(Paragraph(f"<b>IP Address:</b> {session['src_ip']}", styles['Normal']))
        Story.append(Paragraph(f"<b>Classification:</b> {session['attacker_type']} (Confidence: {session.get('confidence', 0)})", styles['Normal']))
        Story.append(Paragraph(f"<b>Reasoning:</b> {session.get('reasoning', '')}", styles['Normal']))
        Story.append(Spacer(1, 12))
        
        # Commands
        Story.append(Paragraph("<b>Commands Executed:</b>", styles['Heading2']))
        for cmd in session['commands']:
            Story.append(Paragraph(f"> {cmd}", styles['Code']))
            
        Story.append(Spacer(1, 12))
        
        # Summary via AI
        prompt = f"Write a one paragraph executive summary of this attacker's behavior. They are a {session['attacker_type']} and ran these commands: {session['commands']}"
        try:
            resp = client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": prompt}]
            )
            summary = resp.choices[0].message.content
        except Exception:
            summary = "AI summary generation failed."
            
        Story.append(Paragraph("<b>AI Summary:</b>", styles['Heading2']))
        Story.append(Paragraph(summary, styles['Normal']))
        
        doc.build(Story)
        print(f"[Reporter] Generated PDF: {pdf_path}")
        return pdf_path
        
    except Exception as e:
        print(f"[Reporter] Error generating report: {e}")
        return None
