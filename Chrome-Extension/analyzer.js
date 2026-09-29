// Phishy Chrome analyzer: intentionally mirrors the website analyzer.py scoring rules.
const SUSPICIOUS_TLDS = [
  ".xyz",
  ".top",
  ".click",
  ".work",
  ".zip",
  ".mov",
  ".info",
  ".tk",
  ".ru",
];
const SHORTENERS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
];
const URGENT = [
  "urgent",
  "immediately",
  "verify now",
  "account suspended",
  "act now",
  "password expires",
  "final warning",
  "click here",
  "limited time",
];

function emailDomain(value = "") {
  const m = String(value).match(/[\w.+-]+@([\w.-]+)/i);
  return m ? m[1].toLowerCase() : "";
}
function cleanUrl(v = "") {
  return String(v)
    .trim()
    .replace(/[.,);\]}>]+$/, "");
}
function analyzeUrl(value) {
  const url = cleanUrl(value);
  let host = "";
  const reasons = [];
  let score = 0;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return {
      url,
      domain: "Invalid URL",
      score: 20,
      reasons: ["Malformed or unreadable URL"],
    };
  }
  if (!host)
    return {
      url,
      domain: "Invalid URL",
      score: 20,
      reasons: ["Malformed or unreadable URL"],
    };
  if (SHORTENERS.includes(host)) {
    score += 18;
    reasons.push("URL shortener hides the final destination");
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    score += 25;
    reasons.push("Uses an IP address instead of a normal domain");
  }
  if (host.includes("xn--")) {
    score += 22;
    reasons.push("Punycode domain may visually imitate another domain");
  }
  try {
    if (url.split("://")[1].split("/")[0].includes("@")) {
      score += 18;
      reasons.push("Contains @ in the authority section");
    }
  } catch {}
  if ((host.match(/\./g) || []).length >= 4) {
    score += 10;
    reasons.push("Unusually high number of subdomains");
  }
  if (url.length > 120) {
    score += 8;
    reasons.push("Unusually long URL");
  }
  if (SUSPICIOUS_TLDS.some((t) => host.endsWith(t))) {
    score += 12;
    reasons.push("Uses a TLD commonly seen in disposable or suspicious links");
  }
  if (
    [
      "login",
      "verify",
      "secure",
      "update",
      "account",
      "bank",
      "signin",
      "password",
    ].some((w) => host.includes(w))
  ) {
    score += 8;
    reasons.push("Domain contains credential-themed wording");
  }
  return {
    url,
    domain: host,
    score: Math.min(score, 40),
    reasons: reasons.length
      ? reasons
      : ["No obvious URL-pattern warning found"],
  };
}
function analyzeEmail(data) {
  const sender = data.sender || "",
    replyTo = data.replyTo || "",
    returnPath = data.returnPath || "",
    messageId = data.messageId || "";
  const senderDomain = emailDomain(sender),
    replyDomain = emailDomain(replyTo),
    returnPathDomain = emailDomain(returnPath),
    messageIdDomain = emailDomain(messageId);
  const subject = data.subject || "(No subject)",
    body = data.body || "";
  const evidence = [];
  let score = 0;
  const add = (severity, title, detail, points) => {
    score += points;
    evidence.push({ severity, title, detail, points });
  };

  if (replyDomain && senderDomain && replyDomain !== senderDomain)
    add(
      "high",
      "Reply-To mismatch",
      `Message is from ${senderDomain} but replies go to ${replyDomain}.`,
      22,
    );
  if (
    senderDomain &&
    (senderDomain.includes("xn--") ||
      SUSPICIOUS_TLDS.some((t) => senderDomain.endsWith(t)))
  )
    add(
      "high",
      "Suspicious sender domain",
      `The sender domain ${senderDomain} has a risky domain pattern.`,
      18,
    );

  // A normal Gmail DOM scan does not reliably expose raw Authentication-Results.
  // Keep the same website fields but mark unavailable rather than inventing pass/fail.
  const auth = {
    spf: "not provided",
    dkim: "not provided",
    dmarc: "not provided",
  };

  const combined = (subject + " " + body).toLowerCase();
  const urgentHits = URGENT.filter((w) => combined.includes(w));
  if (urgentHits.length) {
    const pts = Math.min(18, 5 + urgentHits.length * 3);
    add(
      "medium",
      "Urgent or pressuring language",
      `Detected: ${urgentHits.slice(0, 5).join(", ")}.`,
      pts,
    );
  }

  const urlResults = (data.links || []).slice(0, 20).map(analyzeUrl);
  const riskyUrlPoints = Math.min(
    30,
    urlResults
      .filter((r) => r.score > 0)
      .reduce((s, r) => s + Math.min(15, r.score), 0),
  );
  if (riskyUrlPoints)
    add(
      "high",
      "Suspicious URL patterns",
      `${urlResults.filter((r) => r.score > 0).length} link(s) contain warning indicators.`,
      riskyUrlPoints,
    );

  const riskyExt = [
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".bat",
    ".cmd",
    ".iso",
    ".html",
    ".htm",
    ".zip",
  ];
  const riskyFiles = (data.attachments || []).filter((f) =>
    riskyExt.some((ext) => String(f).toLowerCase().endsWith(ext)),
  );
  if (riskyFiles.length)
    add(
      "high",
      "Risky attachment type",
      `Potentially dangerous attachment(s): ${riskyFiles.join(", ")}.`,
      18,
    );
  if (!evidence.length)
    evidence.push({
      severity: "safe",
      title: "No strong rule-based indicators",
      detail:
        "The supplied content did not trigger the analyzer’s current phishing rules.",
      points: 0,
    });

  const rawScore = score;
  score = Math.min(score, 100);
  const risk = score >= 70 ? "High" : score >= 40 ? "Medium" : "Low";
  const verdict =
    risk === "High" ? "AVOID" : risk === "Medium" ? "CAUTION" : "TRUSTED";
  const recommendation =
    risk === "High"
      ? "Do not click links, open attachments, or reply. Verify the request through a trusted channel and report the message."
      : risk === "Medium"
        ? "Verify the sender and destination URLs before taking action. Use a trusted channel for sensitive requests."
        : "No strong indicators were detected, but still verify unexpected requests before sharing credentials or sensitive data.";

  const identityChecks = [];
  if (replyDomain && senderDomain)
    identityChecks.push({
      label: "From vs Reply-To",
      status: replyDomain !== senderDomain ? "mismatch" : "match",
      detail: `${senderDomain} → ${replyDomain}`,
    });
  if (returnPathDomain && senderDomain)
    identityChecks.push({
      label: "From vs Return-Path",
      status: returnPathDomain !== senderDomain ? "mismatch" : "match",
      detail: `${senderDomain} → ${returnPathDomain}`,
    });
  if (messageIdDomain && senderDomain)
    identityChecks.push({
      label: "From vs Message-ID domain",
      status: messageIdDomain !== senderDomain ? "mismatch" : "match",
      detail: `${senderDomain} → ${messageIdDomain}`,
    });
  const scoreBreakdown = evidence
    .filter((x) => x.points > 0)
    .map((x) => ({ title: x.title, points: x.points, detail: x.detail }));

  return {
    source: "Gmail page scan",
    subject,
    sender: sender || "Not provided",
    reply_to: replyTo || "Not provided",
    return_path: returnPath || "Not provided",
    message_id: messageId || "Not provided",
    sender_domain: senderDomain || "Not available",
    reply_domain: replyDomain || "Not available",
    return_path_domain: returnPathDomain || "Not available",
    message_id_domain: messageIdDomain || "Not available",
    identity_checks: identityChecks,
    score,
    raw_score: rawScore,
    score_breakdown: scoreBreakdown,
    risk,
    verdict,
    authentication: auth,
    urls: urlResults,
    attachments: data.attachments || [],
    evidence,
    recommendation,
    scannedAt: new Date().toISOString(),
  };
}
