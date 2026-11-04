const target = document.getElementById("target");
const scanBtn = document.getElementById("scanBtn");
const terminal = document.getElementById("console");
const results = document.getElementById("results");

function log(message) {
  const time = new Date().toLocaleTimeString();
  terminal.textContent += `\n[${time}] ${message}`;
  terminal.scrollTop = terminal.scrollHeight;
}

scanBtn.addEventListener("click", async () => {
  const url = target.value.trim();
  if (!url) return log("ERROR: Target URL required.");

  let parsed;
  try {
    parsed = new URL(url);
    if (parsed.protocol !== "https:") throw new Error("HTTPS required");
  } catch (error) {
    return log("ERROR: " + error.message);
  }

  scanBtn.disabled = true;
  terminal.textContent = "[SYSTEM] Initializing scanner...";
  results.textContent = "Scanning...";
  log("Submitting target to configured lab scanner...");

  try {
    const response = await fetch("/.netlify/functions/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Scan failed");

    for (const item of data.logs || []) log(item);
    results.replaceChildren();

    for (const item of data.results || []) {
      const div = document.createElement("div");
      div.className = "result-item";
      div.textContent = `${item.type}: ${item.status} — ${item.details}`;
      results.appendChild(div);
    }
    log("SCAN COMPLETED.");
  } catch (error) {
    log("ERROR: " + error.message);
    results.textContent = "Scan failed.";
  } finally {
    scanBtn.disabled = false;
  }
});
