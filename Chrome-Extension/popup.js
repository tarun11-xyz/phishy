const $ = (id) => document.getElementById(id);
let current = null;
function esc(v = "") {
  return String(v).replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
}
async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}
function showOnly(id) {
  ["start", "loading", "result", "history", "settings"].forEach((x) =>
    $(x).classList.toggle("hidden", x !== id),
  );
  $("error").textContent = "";
}
async function updateAiStatus() {
  const { geminiApiKey = "" } = await chrome.storage.local.get("geminiApiKey");
  $("aiDot").classList.toggle("on", !!geminiApiKey);
  $("aiStatus").textContent = geminiApiKey
    ? "AI is enabled"
    : "Now detect Phishing emails easily";
}
async function scan() {
  showOnly("loading");
  $("loadingText").textContent = "Reading this email…";
  try {
    const tab = await activeTab();
    if (!tab?.url?.startsWith("https://mail.google.com/"))
      throw new Error("Open Gmail and open an email first.");
    const response = await chrome.tabs.sendMessage(tab.id, {
      type: "PHISHY_SCAN_PAGE",
    });
    if (!response?.ok)
      throw new Error(response?.error || "Could not read this email.");
    const rules = analyzeEmail(response.email);
    const { geminiApiKey = "" } =
      await chrome.storage.local.get("geminiApiKey");
    let ai = null;
    if (geminiApiKey) {
      $("loadingText").textContent = "Asking Gemini to review the evidence…";
      try {
        ai = await analyzeWithGemini(response.email, rules, geminiApiKey);
      } catch (e) {
        $("error").textContent = e.message;
      }
    }
    current = { ...rules, ai, emailSnapshot: response.email };
    render(current);
  } catch (e) {
    showOnly("start");
    $("error").textContent = e.message.includes("Receiving end")
      ? "Reload Gmail once after updating Phishy, then try again."
      : e.message;
  }
}
function render(r) {
  showOnly("result");
  $("verdict").textContent = r.verdict;
  $("score").textContent = r.score;
  $("summary").textContent = r.recommendation;
  const c = $("verdictCard");
  c.className = "verdict " + r.verdict.toLowerCase();
  $("engineBadge").textContent = r.ai
    ? "WEBSITE SCORE + AI EXPLANATION"
    : "WEBSITE SCORE";
  $("messageInfo").innerHTML =
    `<div class="row"><span>Subject</span><b>${esc(r.subject)}</b></div><div class="row"><span>Sender</span><b>${esc(r.sender)}</b></div><div class="row"><span>Domain</span><b>${esc(r.sender_domain)}</b></div>`;
  $("aiReasons").innerHTML = r.ai
    ? `<div class="ai-reason"><b>AI explanation:</b> ${esc(r.ai.summary || "")}</div>` +
      (r.ai.reasons || [])
        .map((x) => `<div class="ai-reason">${esc(x)}</div>`)
        .join("")
    : '<p class="muted">Gemini is optional and does not change the official Phishy score.</p>';
  $("scoreBreakdown").innerHTML = r.score_breakdown.length
    ? r.score_breakdown
        .map(
          (x) =>
            `<div class="item"><div><b>${esc(x.title)}</b><p>${esc(x.detail)}</p></div><strong>+${x.points}</strong></div>`,
        )
        .join("")
    : '<p class="muted">No risk points added.</p>';
  $("identityChecks").innerHTML = r.identity_checks.length
    ? r.identity_checks
        .map(
          (x) =>
            `<div class="item"><div><b>${esc(x.label)}</b><p>${esc(x.detail)}</p></div><strong>${esc(x.status.toUpperCase())}</strong></div>`,
        )
        .join("")
    : '<p class="muted">No additional identity fields were exposed by the Gmail page.</p>';
  $("auth").innerHTML = ["SPF", "DKIM", "DMARC"]
    .map(
      (k) =>
        `<div class="row"><span>${k}</span><b>${esc(r.authentication[k.toLowerCase()])}</b></div>`,
    )
    .join("");
  $("evidence").innerHTML = r.evidence
    .map(
      (x) =>
        `<div class="item"><div><b>${esc(x.title)}</b><p>${esc(x.detail)}</p></div><strong>${x.points ? `+${x.points}` : "INFO"}</strong></div>`,
    )
    .join("");
  $("links").innerHTML = r.urls.length
    ? r.urls
        .map(
          (x) =>
            `<div class="item"><div><b>${esc(x.domain)}</b><p>${esc(x.reasons.join(" · "))}</p></div><strong>${x.score ? "WARN" : "OK"}</strong></div>`,
        )
        .join("")
    : '<p class="muted">No links detected in this visible message.</p>';
}
$("scanBtn").onclick = scan;
$("detailsBtn").onclick = () => {
  const d = $("details"),
    opening = d.classList.contains("hidden");
  d.classList.toggle("hidden");
  $("detailsBtn").textContent = opening ? "Hide details" : "View details";
};
$("saveBtn").onclick = async () => {
  if (!current) return;
  const { reports = [] } = await chrome.storage.local.get("reports");
  reports.unshift({ ...current, id: crypto.randomUUID() });
  await chrome.storage.local.set({ reports: reports.slice(0, 30) });
  $("saveBtn").textContent = "Saved ✓";
  setTimeout(() => ($("saveBtn").textContent = "Save report"), 1200);
};
$("historyBtn").onclick = showHistory;
$("backBtn").onclick = () => showOnly("start");
async function showHistory() {
  showOnly("history");
  const { reports = [] } = await chrome.storage.local.get("reports");
  $("historyList").innerHTML = reports.length
    ? reports
        .map(
          (r) =>
            `<div class="historyitem"><div><b>${esc(r.subject)}</b><p>${esc(r.sender)}</p><small>${new Date(r.scannedAt).toLocaleString()}</small></div><span class="mini ${r.verdict.toLowerCase()}">${r.verdict} ${r.score}</span></div>`,
        )
        .join("")
    : '<p class="muted">No saved reports yet.</p>';
}
$("settingsBtn").onclick = async () => {
  showOnly("settings");
  const { geminiApiKey = "" } = await chrome.storage.local.get("geminiApiKey");
  $("apiKey").value = geminiApiKey;
};
$("settingsBack").onclick = () => showOnly("start");
$("saveKey").onclick = async () => {
  const key = $("apiKey").value.trim();
  if (!key) {
    $("error").textContent = "Paste a Gemini API key first.";
    return;
  }
  await chrome.storage.local.set({ geminiApiKey: key });
  $("error").textContent = "";
  $("saveKey").textContent = "Saved ✓";
  setTimeout(() => {
    $("saveKey").textContent = "Save API key";
    showOnly("start");
    updateAiStatus();
  }, 700);
};
$("removeKey").onclick = async () => {
  await chrome.storage.local.remove("geminiApiKey");
  $("apiKey").value = "";
  showOnly("start");
  updateAiStatus();
};
updateAiStatus();
