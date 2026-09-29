# Phishy — Phishing Investigation & Email Analyzer

A simple Flask hackathon project that analyzes supplied email samples and explains the evidence behind its phishing-risk classification.

## Features
- Upload `.eml` files or paste complete email/header text
- Sender and Reply-To domain comparison
- URL extraction and suspicious URL pattern checks
- SPF, DKIM and DMARC result parsing when supplied in the message
- Urgency/social-engineering keyword detection
- Attachment-type inspection
- Transparent 0–100 evidence-based risk score
- Low / Medium / High classification
- User-friendly safety recommendation
- PDF investigation report
- Responsive glass-style dashboard
- Built-in suspicious sample for demo use

## Project map
```
phishy_hackathon/
├── app.py              # Flask routes and PDF report generation
├── analyzer.py         # Email parsing, checks and risk scoring
├── requirements.txt    # Minimal Python dependencies
├── README.md           # Setup and explanation
├── templates/
│   └── index.html      # Dashboard structure
└── static/
    ├── style.css       # Responsive visual design
    └── script.js       # Tabs, upload, API call and result rendering
```

## Run
```bash
pip install -r requirements.txt
python app.py
```
Then open `http://127.0.0.1:5000`.

## Data flow
`Email input → /analyze → analyzer.py → evidence + score → JSON → dashboard → optional PDF report`

## Risk scoring
The prototype uses transparent rules rather than a hidden AI decision. Examples include Reply-To mismatch, authentication failures, suspicious URL patterns, urgent wording and risky attachment types. The final score is capped at 100.

- 0–39: Low
- 40–69: Medium
- 70–100: High

This score is an investigation aid, not proof that an email is malicious or safe. A sophisticated phishing message may avoid these rules, while a legitimate message can contain unusual indicators.

## Important functions to understand
- `analyze_email_text()` — coordinates the analysis and scoring
- `analyze_url()` — explains suspicious URL patterns
- `parse_authentication()` — reads supplied SPF/DKIM/DMARC results
- `/analyze` — receives user input and returns analysis JSON
- `/report` — creates the PDF report from the latest result
- `render()` in `script.js` — displays the backend result in the dashboard

## Easy modifications
- Change thresholds or rule points in `analyzer.py`
- Add new suspicious words to `URGENT`
- Add domain/TLD patterns to the URL rules
- Change UI styling in `static/style.css`
- Add organizer-provided reputation data inside `analyze_url()` without restructuring the app

## Demo suggestion
Click **Load suspicious sample**, then **Run investigation**. Explain the result from top to bottom: identity mismatch → authentication failures → urgency → suspicious link → score → safety recommendation → PDF report.
