Phishy Chrome Extension — Website-Matched Scoring
This version ports the website `analyzer.py` scoring rules into `analyzer.js`.
Important behavior
Official score comes only from the same deterministic rules used by the website.
Gemini is optional and explanation-only; it cannot change score or verdict.
Website thresholds are used: Low 0–39, Medium 40–69, High 70–100.
Extension verdict labels map to Low=TRUST, Medium=CAUTION, High=AVOID.
Gmail's normal page does not reliably expose raw SPF/DKIM/DMARC/Return-Path/Message-ID. Missing fields are shown as not provided, never guessed.
Therefore the website and extension produce the same score when they have the same evidence. A raw `.eml` website analysis can score differently because it may contain extra header evidence.
Install
Extract this folder.
Open `chrome://extensions`.
Enable Developer mode.
Click Load unpacked and select this folder.
Reload Gmail once.
Open an email and click Phishy → Scan open email.
Gemini API key is optional under Settings and only adds a plain-language explanation.
