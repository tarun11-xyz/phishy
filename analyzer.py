import re
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse

URL_RE = re.compile(r'https?://[^\s<>"\']+', re.I)
URGENT = ['urgent','immediately','verify now','account suspended','act now','password expires','final warning','click here','limited time']
SUSPICIOUS_TLDS = {'.xyz','.top','.click','.work','.zip','.mov','.info','.tk','.ru'}
SHORTENERS = {'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly'}


def domain_of(value):
    if not value or '@' not in value:
        return ''
    return value.rsplit('@', 1)[-1].strip().strip('>').lower()


def extract_address(header):
    match = re.search(r'<([^>]+)>', header or '')
    return (match.group(1) if match else (header or '')).strip()


def parse_authentication(message):
    """Read authentication verdicts only from authentication-related headers.

    A DKIM-Signature header means a message was signed, not that verification passed.
    Likewise, authentication words appearing in the body must never count as results.
    """
    valid = ('pass', 'fail', 'softfail', 'neutral', 'none', 'temperror', 'permerror')
    results = {'spf': [], 'dkim': [], 'dmarc': []}

    # Authentication-Results is where receiving mail systems normally record
    # SPF/DKIM/DMARC verification outcomes.
    for header in message.get_all('Authentication-Results', []):
        text = str(header).lower()
        for name in results:
            match = re.search(rf'(?:^|[;\s]){name}\s*=\s*({"|".join(valid)})\b', text)
            if match:
                results[name].append(match.group(1))

    # SPF may also be supplied in the dedicated Received-SPF header.
    for header in message.get_all('Received-SPF', []):
        match = re.match(r'\s*(pass|fail|softfail|neutral|none|temperror|permerror)\b', str(header).lower())
        if match:
            results['spf'].append(match.group(1))

    # Prefer a failure/error over a pass when multiple hops report different results.
    priority = ('fail', 'softfail', 'permerror', 'temperror', 'neutral', 'none', 'pass')
    final = {}
    for name, values in results.items():
        final[name] = next((value for value in priority if value in values), 'not provided')
    return final


def analyze_url(url):
    clean = url.rstrip('.,);]}>')
    try:
        parsed = urlparse(clean)
        host = (parsed.hostname or '').lower()
    except ValueError:
        host = ''
    reasons, score = [], 0
    if not host:
        return {'url': clean, 'domain': 'Invalid URL', 'score': 20, 'reasons': ['Malformed or unreadable URL']}
    if host in SHORTENERS:
        score += 18; reasons.append('URL shortener hides the final destination')
    if re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host):
        score += 25; reasons.append('Uses an IP address instead of a normal domain')
    if 'xn--' in host:
        score += 22; reasons.append('Punycode domain may visually imitate another domain')
    if '@' in clean.split('://',1)[-1].split('/')[0]:
        score += 18; reasons.append('Contains @ in the authority section')
    if host.count('.') >= 4:
        score += 10; reasons.append('Unusually high number of subdomains')
    if len(clean) > 120:
        score += 8; reasons.append('Unusually long URL')
    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 12; reasons.append('Uses a TLD commonly seen in disposable or suspicious links')
    suspicious_words = ['login','verify','secure','update','account','bank','signin','password']
    if any(w in host for w in suspicious_words):
        score += 8; reasons.append('Domain contains credential-themed wording')
    return {'url': clean, 'domain': host, 'score': min(score, 40), 'reasons': reasons or ['No obvious URL-pattern warning found']}


def analyze_email_text(raw_text, source='Pasted email'):
    raw_bytes = raw_text.encode('utf-8', errors='replace')
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    from_header = str(msg.get('From', ''))
    reply_header = str(msg.get('Reply-To', ''))
    return_path_header = str(msg.get('Return-Path', ''))
    message_id = str(msg.get('Message-ID', ''))
    subject = str(msg.get('Subject', '(No subject)'))
    sender = extract_address(from_header)
    reply_to = extract_address(reply_header)
    return_path = extract_address(return_path_header)
    sender_domain = domain_of(sender)
    reply_domain = domain_of(reply_to)
    return_path_domain = domain_of(return_path)
    message_id_domain = ''
    if '@' in message_id:
        message_id_domain = message_id.rsplit('@', 1)[-1].strip().strip('>').lower()

    body_parts = []
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            filename = part.get_filename()
            if filename:
                attachments.append(filename)
            if part.get_content_type() in ('text/plain','text/html') and not filename:
                try: body_parts.append(part.get_content())
                except Exception: pass
    else:
        try: body_parts.append(msg.get_content())
        except Exception: body_parts.append(raw_text)
    body = '\n'.join(body_parts) or raw_text
    urls = list(dict.fromkeys(URL_RE.findall(body)))
    url_results = [analyze_url(u) for u in urls[:20]]
    auth = parse_authentication(msg)

    evidence = []
    score = 0
    if reply_domain and sender_domain and reply_domain != sender_domain:
        score += 22; evidence.append({'severity':'high','title':'Reply-To mismatch','detail':f'Message is from {sender_domain} but replies go to {reply_domain}.','points':22})
    if sender_domain and ('xn--' in sender_domain or any(sender_domain.endswith(t) for t in SUSPICIOUS_TLDS)):
        score += 18; evidence.append({'severity':'high','title':'Suspicious sender domain','detail':f'The sender domain {sender_domain} has a risky domain pattern.','points':18})
    for name, value in auth.items():
        if value in ('fail','softfail','permerror'):
            pts = 14 if name == 'dmarc' else 10
            score += pts; evidence.append({'severity':'high','title':f'{name.upper()} {value}','detail':f'Authentication result reports {name.upper()}={value}.','points':pts})
        elif value == 'pass':
            evidence.append({'severity':'safe','title':f'{name.upper()} passed','detail':f'Authentication information reports {name.upper()}=pass.','points':0})
    urgent_hits = [w for w in URGENT if w in (subject+' '+body).lower()]
    if urgent_hits:
        pts = min(18, 5 + len(urgent_hits)*3); score += pts
        evidence.append({'severity':'medium','title':'Urgent or pressuring language','detail':'Detected: '+', '.join(urgent_hits[:5])+'.','points':pts})
    risky_url_points = min(30, sum(min(15, r['score']) for r in url_results if r['score'] > 0))
    if risky_url_points:
        score += risky_url_points; evidence.append({'severity':'high','title':'Suspicious URL patterns','detail':f'{sum(1 for r in url_results if r["score"]>0)} link(s) contain warning indicators.','points':risky_url_points})
    risky_ext = ('.exe','.scr','.js','.vbs','.bat','.cmd','.iso','.html','.htm','.zip')
    risky_files = [f for f in attachments if f.lower().endswith(risky_ext)]
    if risky_files:
        score += 18; evidence.append({'severity':'high','title':'Risky attachment type','detail':'Potentially dangerous attachment(s): '+', '.join(risky_files)+'.','points':18})
    if not evidence:
        evidence.append({'severity':'safe','title':'No strong rule-based indicators','detail':'The supplied content did not trigger the analyzer’s current phishing rules.','points':0})

    raw_score = score
    score = min(score, 100)
    risk = 'High' if score >= 70 else 'Medium' if score >= 40 else 'Low'
    recommendation = ('Do not click links, open attachments, or reply. Verify the request through a trusted channel and report the message.' if risk == 'High'
                      else 'Verify the sender and destination URLs before taking action. Use a trusted channel for sensitive requests.' if risk == 'Medium'
                      else 'No strong indicators were detected, but still verify unexpected requests before sharing credentials or sensitive data.')
    identity_checks = []
    if reply_domain and sender_domain:
        identity_checks.append({
            'label': 'From vs Reply-To',
            'status': 'mismatch' if reply_domain != sender_domain else 'match',
            'detail': f'{sender_domain} → {reply_domain}'
        })
    if return_path_domain and sender_domain:
        identity_checks.append({
            'label': 'From vs Return-Path',
            'status': 'mismatch' if return_path_domain != sender_domain else 'match',
            'detail': f'{sender_domain} → {return_path_domain}'
        })
    if message_id_domain and sender_domain:
        identity_checks.append({
            'label': 'From vs Message-ID domain',
            'status': 'mismatch' if message_id_domain != sender_domain else 'match',
            'detail': f'{sender_domain} → {message_id_domain}'
        })

    score_breakdown = [
        {'title': item['title'], 'points': item['points'], 'detail': item['detail']}
        for item in evidence if item.get('points', 0) > 0
    ]

    return {
        'source': source, 'subject': subject,
        'sender': sender or 'Not provided', 'reply_to': reply_to or 'Not provided',
        'return_path': return_path or 'Not provided', 'message_id': message_id or 'Not provided',
        'sender_domain': sender_domain or 'Not available', 'reply_domain': reply_domain or 'Not available',
        'return_path_domain': return_path_domain or 'Not available',
        'message_id_domain': message_id_domain or 'Not available',
        'identity_checks': identity_checks,
        'score': score, 'raw_score': raw_score, 'score_breakdown': score_breakdown,
        'risk': risk, 'authentication': auth, 'urls': url_results,
        'attachments': attachments, 'evidence': evidence, 'recommendation': recommendation
    }


def parse_eml(file_bytes, filename='email.eml'):
    return analyze_email_text(file_bytes.decode('utf-8', errors='replace'), filename)
