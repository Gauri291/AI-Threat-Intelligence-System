from fpdf import FPDF
from datetime import datetime
import os


class ThreatReport(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 14)
        self.cell(0, 10, "AI Threat Intelligence Report", ln=True, align="C")

        self.set_font("Helvetica", "", 9)
        self.cell(
            0,
            6,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ln=True,
            align="C"
        )

        self.ln(5)


def generate_pdf(
    analysis: dict,
    anomaly_count: int,
    output="reports/incident_report.pdf"
):
    os.makedirs("reports", exist_ok=True)

    pdf = ThreatReport()
    pdf.add_page()

    # Threat Name
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(
        0,
        10,
        f"Threat: {analysis.get('threat_name', 'Unknown')}",
        ln=True
    )

    # Executive Summary
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(
        190,
        8,
        analysis.get(
            "executive_summary",
            "No summary available."
        )
    )

    pdf.ln(5)

    # Confidence and Count
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(
        0,
        10,
        f"Confidence: {analysis.get('confidence', 'N/A')} | Anomalies Detected: {anomaly_count}",
        ln=True
    )

    pdf.ln(5)

    # Attack Vector
    pdf.cell(
        0,
        10,
        f"Attack Vector: {analysis.get('attack_vector', 'Unknown')}",
        ln=True
    )

    pdf.ln(5)

    # Recommended Actions
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 10, "Recommended Actions", ln=True)

    pdf.set_font("Helvetica", "", 10)

    for action in analysis.get("recommended_actions", []):
        pdf.cell(0, 8, f"- {action}", ln=True)

    pdf.output(output)

    return output