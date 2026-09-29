const tabs = document.querySelectorAll(".tab");
const panels = {
  upload: document.getElementById("uploadPanel"),
  paste: document.getElementById("pastePanel"),
};
tabs.forEach((tab) =>
  tab.addEventListener("click", () => {
    tabs.forEach((t) => t.classList.remove("active"));
    Object.values(panels).forEach((p) => p.classList.remove("active"));
    tab.classList.add("active");
    panels[tab.dataset.tab].classList.add("active");
  }),
);
const fileInput = document.getElementById("emailFile"),
  fileName = document.getElementById("fileName"),
  dropzone = document.getElementById("dropzone");
fileInput.addEventListener(
  "change",
  () => (fileName.textContent = fileInput.files[0]?.name || ""),
);
["dragenter", "dragover"].forEach((e) =>
  dropzone.addEventListener(e, (x) => {
    x.preventDefault();
    dropzone.classList.add("drag");
  }),
);
["dragleave", "drop"].forEach((e) =>
  dropzone.addEventListener(e, (x) => {
    x.preventDefault();
    dropzone.classList.remove("drag");
  }),
);
dropzone.addEventListener("drop", (e) => {
  if (e.dataTransfer.files.length) {
    fileInput.files = e.dataTransfer.files;
    fileName.textContent = e.dataTransfer.files[0].name;
  }
});
const sample = `From: IT Support <security@college-support.xyz>\nReply-To: resetdesk@account-verify.top\nSubject: URGENT: Verify now - password expires today\nAuthentication-Results: mail.college.edu; spf=fail; dkim=fail; dmarc=fail\nContent-Type: text/plain; charset=UTF-8\n\nYour college account will be suspended. Verify now using the secure login below:\nhttp://college-login.verify.account-security.xyz/login\n\nAct now to avoid losing access.`;
document.getElementById("sampleBtn").addEventListener("click", () => {
  // The sample must be analyzed as pasted text, never as a previously selected .eml file.
  fileInput.value = "";
  fileName.textContent = "";
  document.querySelector('[data-tab="paste"]').click();
  document.getElementById("emailText").value = sample;
});
const form = document.getElementById("analysisForm"),
  empty = document.getElementById("emptyState"),
  loading = document.getElementById("loading"),
  results = document.getElementById("results"),
  error = document.getElementById("formError");
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  error.textContent = "";
  empty.classList.add("hidden");
  results.classList.add("hidden");
  loading.classList.remove("hidden");
  try {
    const formData = new FormData(form);
    const pasteIsActive = panels.paste.classList.contains("active");
    if (pasteIsActive) {
      formData.delete("email_file");
    } else {
      formData.delete("email_text");
    }
    const response = await fetch("/analyze", {
      method: "POST",
      body: formData,
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Analysis failed");
    render(data);
  } catch (err) {
    empty.classList.remove("hidden");
    error.textContent = err.message;
  } finally {
    loading.classList.add("hidden");
  }
});
function render(data) {
  results.classList.remove("hidden");

  // Keep the main output minimal. Detailed evidence stays available on demand.
  const details = document.getElementById("resultDetails");
  const detailsToggle = document.getElementById("detailsToggle");
  details?.classList.add("hidden");
  if (detailsToggle) {
    detailsToggle.textContent = "View details";
    detailsToggle.setAttribute("aria-expanded", "false");
  }

  document.getElementById("resultSubject").textContent =
    data.subject || "Email analysis result";

  document.getElementById("riskScore").textContent = data.score ?? 0;

  const ring = document.getElementById("riskRing");
  const color =
    data.risk === "High"
      ? "#b83245"
      : data.risk === "Medium"
        ? "#a56a00"
        : "#267557";
  ring.style.background = `conic-gradient(${color} ${(data.score || 0) * 3.6}deg,#dbe4ee 0)`;

  const badge = document.getElementById("riskBadge");
  badge.textContent = `${(data.risk || "Low").toUpperCase()} RISK`;
  badge.className = `risk-badge ${(data.risk || "Low").toLowerCase()}`;

  document.getElementById("senderSummary").textContent =
    `${data.sender || "Unknown sender"} → Reply-To: ${data.reply_to || "Not provided"}`;

  renderHeaderForensics(data);
  renderScoreBreakdown(data);

  const authGrid = document.getElementById("authGrid");
  authGrid.innerHTML = Object.entries(data.authentication || {})
    .map(([key, value]) => {
      const state = String(value).toLowerCase();
      const statusClass = state.includes("pass")
        ? "pass"
        : state.includes("fail") || state.includes("error")
          ? "fail"
          : "unknown";
      return `<div class="auth-box ${statusClass}"><span class="auth-name">${escapeHtml(key.toUpperCase())}</span><strong class="auth-status">${escapeHtml(value)}</strong></div>`;
    })
    .join("");

  const evidenceList = document.getElementById("evidenceList");
  const evidence = data.evidence || [];
  evidenceList.innerHTML = evidence.length
    ? evidence
        .map(
          (item) =>
            `<div class="evidence-item"><div class="evidence-content"><div class="evidence-title"><i class="sev ${escapeHtml(item.severity || "")}"></i><b>${escapeHtml(item.title || "Security indicator")}</b></div><p>${escapeHtml(item.detail || "")}</p></div><span class="points">${item.points ? `+${item.points}` : "INFO"}</span></div>`,
        )
        .join("")
    : `<div class="evidence-empty">No major suspicious indicators were detected.</div>`;

  const urlSection = document.getElementById("urlSection");
  const urls = data.urls || [];
  if (urls.length) {
    urlSection.classList.remove("hidden");
    document.getElementById("urlList").innerHTML = urls
      .map(
        (item) =>
          `<div class="url-item"><div class="url-heading"><b>${escapeHtml(item.domain || "Detected URL")}</b><span>${item.score ? "Warning" : "No obvious warning"}</span></div><code>${escapeHtml(item.url || "")}</code>${item.reasons?.length ? `<p>${escapeHtml(item.reasons.join(" · "))}</p>` : ""}</div>`,
      )
      .join("");
  } else {
    urlSection.classList.add("hidden");
    document.getElementById("urlList").innerHTML = "";
  }

  document.getElementById("recommendation").textContent =
    data.recommendation || "Review the detected evidence before interacting with this email.";

  renderQuickVerdict(data);

  if (window.innerWidth <= 900) {
    setTimeout(() => results.scrollIntoView({ behavior: "smooth", block: "start" }), 120);
  }
}

function verdictFor(data) {
  const score = Number(data.score || 0);
  if (score >= 70) return { word: "AVOID", cls: "avoid", text: "Multiple strong phishing indicators were detected. Do not click links, open attachments, or reply until independently verified." };
  if (score >= 40) return { word: "CAUTION", cls: "caution", text: "Some suspicious indicators were detected. Verify the sender and message through a trusted channel before acting." };
  return { word: "TRUST", cls: "trust", text: "No major warning indicators were detected by the current checks. Still verify unexpected requests before sharing sensitive information." };
}

function renderQuickVerdict(data) {
  const verdict = verdictFor(data);
  const quick = document.getElementById("quickVerdict");
  const popup = document.querySelector(".verdict-popup");
  [quick, popup].forEach((el) => {
    if (!el) return;
    el.classList.remove("trust", "caution", "avoid");
    el.classList.add(verdict.cls);
  });
  document.getElementById("quickVerdictWord").textContent = verdict.word;
  document.getElementById("quickVerdictText").textContent = verdict.text;
  document.getElementById("verdictWord").textContent = verdict.word;
  document.getElementById("verdictSummary").textContent = verdict.text;
  document.getElementById("verdictScore").textContent = `${Number(data.score || 0)}/100`;
  const overlay = document.getElementById("verdictOverlay");
  overlay?.classList.remove("hidden");
  overlay?.setAttribute("aria-hidden", "false");
}

function closeVerdict() {
  const overlay = document.getElementById("verdictOverlay");
  overlay?.classList.add("hidden");
  overlay?.setAttribute("aria-hidden", "true");
}

document.getElementById("verdictClose")?.addEventListener("click", closeVerdict);
document.getElementById("verdictOverlay")?.addEventListener("click", (event) => {
  if (event.target.id === "verdictOverlay") closeVerdict();
});
document.getElementById("detailsToggle")?.addEventListener("click", () => {
  const details = document.getElementById("resultDetails");
  const button = document.getElementById("detailsToggle");
  const opening = details?.classList.contains("hidden");
  details?.classList.toggle("hidden");
  if (button) {
    button.textContent = opening ? "Hide details" : "View details";
    button.setAttribute("aria-expanded", opening ? "true" : "false");
  }
});
document.getElementById("verdictDetailsBtn")?.addEventListener("click", () => {
  closeVerdict();
  const details = document.getElementById("resultDetails");
  const button = document.getElementById("detailsToggle");
  details?.classList.remove("hidden");
  if (button) { button.textContent = "Hide details"; button.setAttribute("aria-expanded", "true"); }
  document.getElementById("results")?.scrollIntoView({ behavior: "smooth", block: "start" });
});

function escapeHtml(value) {
  return String(value).replace(
    /[&<>'"]/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[
        c
      ],
  );
}


function renderHeaderForensics(data) {
  const grid = document.getElementById("forensicsGrid");
  const checks = document.getElementById("identityChecks");
  if (!grid || !checks) return;

  const fields = [
    ["From", data.sender || "Not provided"],
    ["Reply-To", data.reply_to || "Not provided"],
    ["Return-Path", data.return_path || "Not provided"],
    ["Message-ID", data.message_id || "Not provided"],
    ["Sending domain", data.sender_domain || "Not available"],
    ["Message-ID domain", data.message_id_domain || "Not available"],
  ];

  grid.innerHTML = fields.map(([label, value]) =>
    `<div class="forensic-field"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`
  ).join("");

  const identityChecks = data.identity_checks || [];
  checks.innerHTML = identityChecks.length
    ? identityChecks.map((item) => {
        const status = item.status === "mismatch" ? "mismatch" : "match";
        const word = status === "mismatch" ? "Mismatch" : "Match";
        return `<div class="identity-check ${status}"><div><b>${escapeHtml(item.label)}</b><small>${escapeHtml(item.detail || "")}</small></div><span>${word}</span></div>`;
      }).join("")
    : `<div class="identity-check neutral"><div><b>Identity comparison</b><small>Not enough header data was provided for a domain comparison.</small></div><span>INFO</span></div>`;
}

function renderScoreBreakdown(data) {
  const container = document.getElementById("scoreBreakdown");
  if (!container) return;
  const items = data.score_breakdown || (data.evidence || []).filter((item) => Number(item.points) > 0);

  const rows = items.length
    ? items.map((item) => `<div class="score-row"><div><b>${escapeHtml(item.title || "Risk indicator")}</b><small>${escapeHtml(item.detail || "")}</small></div><strong>+${Number(item.points) || 0}</strong></div>`).join("")
    : `<div class="score-row zero"><div><b>No scored warning indicators</b><small>The current rules did not add risk points.</small></div><strong>+0</strong></div>`;

  const raw = Number(data.raw_score ?? data.score ?? 0);
  const finalScore = Number(data.score ?? 0);
  const capNote = raw > 100 ? `<small class="score-cap">Raw total ${raw}; final risk score is capped at 100.</small>` : "";
  container.innerHTML = `${rows}<div class="score-total"><span>Final risk score</span><strong>${finalScore}/100</strong></div>${capNote}`;
}

// =========================================================
// SAVED REPORTS + RECENT REPORTS
// =========================================================
const saveReportBtn = document.getElementById("saveReportBtn");
const saveStatus = document.getElementById("saveStatus");
const reportsOverlay = document.getElementById("reportsOverlay");
const reportsList = document.getElementById("reportsList");
const recentReportsBtn = document.getElementById("recentReportsBtn");
const resultRecentReportsBtn = document.getElementById("resultRecentReportsBtn");
const closeReportsBtn = document.getElementById("closeReportsBtn");

saveReportBtn?.addEventListener("click", async () => {
  saveReportBtn.disabled = true;
  saveStatus.textContent = "Saving…";
  try {
    const response = await fetch("/reports/save", { method: "POST" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not save report.");
    saveStatus.textContent = "Report saved to Recent reports.";
  } catch (err) {
    saveStatus.textContent = err.message;
  } finally {
    saveReportBtn.disabled = false;
  }
});

async function openRecentReports() {
  reportsOverlay.classList.remove("hidden");
  reportsOverlay.setAttribute("aria-hidden", "false");
  document.body.classList.add("no-scroll");
  reportsList.innerHTML = '<div class="reports-empty">Loading saved reports…</div>';
  try {
    const response = await fetch("/reports");
    const reports = await response.json();
    if (!response.ok) throw new Error("Could not load saved reports.");
    renderRecentReports(reports);
  } catch (err) {
    reportsList.innerHTML = `<div class="reports-empty">${escapeHtml(err.message)}</div>`;
  }
}

function closeRecentReports() {
  reportsOverlay.classList.add("hidden");
  reportsOverlay.setAttribute("aria-hidden", "true");
  document.body.classList.remove("no-scroll");
}

function renderRecentReports(reports) {
  if (!reports.length) {
    reportsList.innerHTML = '<div class="reports-empty">No saved reports yet. Analyze an email and choose “Save report”.</div>';
    return;
  }
  reportsList.innerHTML = reports.map((item) => {
    const risk = String(item.risk || "Unknown").toLowerCase();
    const date = new Date(item.saved_at);
    const displayDate = Number.isNaN(date.getTime()) ? item.saved_at : date.toLocaleString();
    return `<article class="recent-report" data-report-id="${escapeHtml(item.id)}">
      <div class="recent-report-top"><div><h3>${escapeHtml(item.subject || "Untitled email")}</h3><time>${escapeHtml(displayDate)}</time></div><span class="recent-risk ${escapeHtml(risk)}">${escapeHtml(String(item.risk || "Unknown").toUpperCase())} · ${Number(item.score) || 0}/100</span></div>
      <div class="recent-report-meta"><span class="recent-report-sender">${escapeHtml(item.sender || "Unknown sender")}</span></div>
      <div class="recent-report-actions"><a href="/reports/${encodeURIComponent(item.id)}/download">Download PDF</a><button type="button" data-delete-report="${escapeHtml(item.id)}">Delete</button></div>
    </article>`;
  }).join("");
}

reportsList?.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-delete-report]");
  if (!button) return;
  const id = button.dataset.deleteReport;
  button.disabled = true;
  try {
    const response = await fetch(`/reports/${encodeURIComponent(id)}`, { method: "DELETE" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Could not delete report.");
    button.closest(".recent-report")?.remove();
    if (!reportsList.querySelector(".recent-report")) {
      reportsList.innerHTML = '<div class="reports-empty">No saved reports yet.</div>';
    }
  } catch (err) {
    button.disabled = false;
    alert(err.message);
  }
});

recentReportsBtn?.addEventListener("click", openRecentReports);
resultRecentReportsBtn?.addEventListener("click", openRecentReports);
closeReportsBtn?.addEventListener("click", closeRecentReports);
reportsOverlay?.addEventListener("click", (event) => {
  if (event.target === reportsOverlay) closeRecentReports();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !reportsOverlay?.classList.contains("hidden")) closeRecentReports();
});
