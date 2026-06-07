# AI Threat Intelligence System

Real-time network anomaly detection powered by Machine Learning (Isolation Forest) and Google Gemini AI for automated threat analysis.

## Live Demo

https://ai-threat-intelligence-system-bgqhctwtfgzwz2jkjitwnf.streamlit.app/

## Features

- Real-time network log analysis
- Isolation Forest based anomaly detection
- Severity classification (CRITICAL / HIGH / LOW)
- AI-powered threat intelligence using Google Gemini
- Interactive Streamlit dashboard
- PDF incident report generation
- Network activity visualization using Plotly

## Architecture

Log Data
→ Feature Engineering
→ Isolation Forest Model
→ Anomaly Detection
→ Gemini AI Analysis
→ Incident Report Generation
→ Streamlit Dashboard

## Tech Stack

- Python
- Streamlit
- Scikit-learn
- Pandas
- NumPy
- Plotly
- Google Gemini API
- FPDF2

## Project Structure

```
threat-intel-ai/
│
├── app.py
├── detector.py
├── llm_engine.py
├── report_gen.py
├── requirements.txt
├── README.md
├── data/
├── models/
└── utils/
```

## How to Run

```bash
pip install -r requirements.txt
```

Create `.env`

```env
GEMINI_API_KEY=your_api_key
```

Run:

```bash
streamlit run app.py
```

## What I Learned

- Anomaly detection using Isolation Forest
- Feature engineering for cybersecurity data
- Prompt engineering with Gemini AI
- Streamlit dashboard development
- GitHub and cloud deployment
- Automated PDF report generation

## Author

Gauri Yadav

Computer Science & Engineering (IoT, Cybersecurity & Blockchain)

A. C. Patil College of Engineering
