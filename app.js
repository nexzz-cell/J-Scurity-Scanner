const target = document.getElementById("target");
const scanBtn = document.getElementById("scanBtn");
const terminal = document.getElementById("console");
const results = document.getElementById("results");
const sessions = document.getElementById("sessions");

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVERITY_COLOR = {
  critical: "#ff3b3b", high: "#ff8a00", medium: "#d4b800", low: "#5aa9e6", info: "#888"
};

function log(message) {
  const time = new Date().toLocaleTimeString();
  terminal.textContent += `\n[${time}] ${message}`;
  terminal.scrollTop = terminal.scrollHeight;
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function renderSummary(summary, total) {
  const box = document.createElement("div");
  box.className = "summary";
  const parts = [`<strong>${total} findings</strong>`];
  for (const [type, count] of Object.entries(summary)) {
    parts.push(`<span class="chip">${esc(type)}: ${count}</span>`);
  }
  box.innerHTML = parts.join(" ");
  return box;
}

function renderFinding(f) {
  const div = document.createElement("div");
  div.className = "result-item";
  const sev = f.severity || "info";
  div.style.borderLeft = `8px solid ${SEVERITY_COLOR[sev] || "#888"}`;

  const lines = [
    `<div class="finding-head"><span class="sev sev-${esc(sev)}">${esc(sev.toUpperCase())}</span> <strong>${esc(f.type)}</strong></div>`,
    `<div class="finding-line"><span>where</span> <code>${esc(f.where || "")}</code></div>`
  ];
  if (f.method) lines.push(`<div class="finding-line"><span>method</span> <code>${esc(f.method)}</code></div>`);
  if (f.param) lines.push(`<div class="finding-line"><span>param</span> <code>${esc(f.param)}</code></div>`);
  if (f.payload) lines.push(`<div class="finding-line"><span>payload</span> <code class="pl">${esc(f.payload)}</code></div>`);
  if (f.evidence) lines.push(`<div class="finding-line"><span>evidence</span> <code>${esc(f.evidence)}</code></div>`);
  if (f.kind) lines.push(`<div class="finding-line"><span>kind</span> <code>${esc(f.kind)}</code></div>`);
  if (f.baseline) lines.push(`<div class="finding-line"><span>baseline</span> <code>${esc(f.baseline)}</code></div>`);

  div.innerHTML = lines.join("");
  return div;
}

scanBtn.addEventListener("click", async () => {
  const url = target.value.trim();
  if (!url) return log("ERROR: Target URL required.");

  let parsed;
  try {
    parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("http(s) required");
  } catch (error) {
    return log("ERROR: " + error.message);
  }

  scanBtn.disabled = true;
  terminal.textContent = "[SYSTEM] Initializing active scanner...";
  results.textContent = "Scanning...";
  log(`Submitting target: ${parsed.origin}`);

  const body = { url };
  const cookieA = document.getElementById("cookieA")?.value.trim();
  const cookieB = document.getElementById("cookieB")?.value.trim();
  if (cookieA && cookieB) {
    body.sessionA = cookieA;
    body.sessionB = cookieB;
    log("Cross-session IDOR replay armed.");
  }

  try {
    const response = await fetch("/.netlify/functions/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Scan failed");

    for (const item of data.logs || []) log(item);
    results.replaceChildren();

    const findings = (data.findings || []).slice().sort(
      (a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
    );

    results.appendChild(renderSummary(data.summary || {}, findings.length));

    if (!findings.length) {
      const none = document.createElement("div");
      none.className = "result-item";
      none.textContent = "No findings — scan surface may have been blocked, or target is clean on tested vectors.";
      results.appendChild(none);
    } else {
      for (const f of findings) results.appendChild(renderFinding(f));
    }

    log(`SCAN COMPLETED. ${findings.length} findings across ${data.pagesVisited} pages.`);
  } catch (error) {
    log("ERROR: " + error.message);
    results.textContent = "Scan failed.";
  } finally {
    scanBtn.disabled = false;
  }
});