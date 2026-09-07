/* ═══════════════════════════════════════════════════════════════
   VERITRACE — frontend application logic
   ═══════════════════════════════════════════════════════════════ */
const API = "http://localhost:5000/api";

// ── State ──────────────────────────────────────────────────────
let activeUser   = null;  // { user_id, name }
let activeFileId = null;

// ── Utility ────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit"
  });
}

function fileIcon(filename) {
  if (!filename) return "📄";
  const ext = filename.split(".").pop().toLowerCase();
  const map = {
    jpg: "🖼", jpeg: "🖼", png: "🖼", gif: "🖼", webp: "🖼", svg: "🖼",
    pdf: "📑", mp4: "🎬", mov: "🎬", avi: "🎬", mkv: "🎬",
    txt: "📝", doc: "📝", docx: "📝", md: "📝",
    json: "📋", xml: "📋", csv: "📊",
    zip: "📦", tar: "📦", gz: "📦", rar: "📦"
  };
  return map[ext] || "📄";
}

function showResult(elId, data, isError = false) {
  const el = $(elId);
  el.classList.remove("hidden", "error", "success");
  if (typeof data === "object") {
    el.innerHTML = Object.entries(data)
      .map(([k, v]) => `<div class="result-label">${k}</div><div class="result-value">${v}</div>`)
      .join("");
  } else {
    el.textContent = data;
  }
  el.classList.add(isError ? "error" : "success");
}

function setLoading(btnId, loading) {
  const btn = $(btnId);
  if (!btn) return;
  if (loading) {
    btn.dataset.origLabel = btn.textContent;
    btn.innerHTML = `<span class="btn-spinner"></span> Working…`;
    btn.disabled = true;
  } else {
    btn.textContent = btn.dataset.origLabel || btn.textContent;
    btn.disabled = false;
  }
}

// ── Toast system ───────────────────────────────────────────────
function toast(msg, type = "info", duration = 3500) {
  const container = $("toast-container");
  const t = document.createElement("div");
  t.className = `toast toast-${type}`;
  t.textContent = msg;
  container.appendChild(t);
  const dismiss = () => {
    t.classList.add("out");
    setTimeout(() => t.remove(), 320);
  };
  t.addEventListener("click", dismiss);
  setTimeout(dismiss, duration);
}

// ── Clipboard ──────────────────────────────────────────────────
async function copyEl(elId, btn) {
  const text = $(elId)?.textContent?.trim();
  if (!text) return;
  await copyText(text, btn);
  toast("Copied to clipboard!", "success", 1600);
}

async function copyText(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    const orig = btn.textContent;
    btn.textContent = "✓";
    btn.classList.add("copied");
    setTimeout(() => { btn.textContent = orig; btn.classList.remove("copied"); }, 2000);
  } catch {}
}

// ── SHA-256 (client-side via SubtleCrypto) ─────────────────────
async function computeSHA256(file) {
  const buf = await file.arrayBuffer();
  const hashBuf = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hashBuf))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── Drop zones ─────────────────────────────────────────────────
function setupDropZone(zoneId, inputId, filenameId, onFile) {
  const zone = $(zoneId), input = $(inputId), fnEl = $(filenameId);
  zone.addEventListener("dragover",  e  => { e.preventDefault(); zone.classList.add("dragover"); });
  zone.addEventListener("dragleave", ()  => zone.classList.remove("dragover"));
  zone.addEventListener("drop",      e  => {
    e.preventDefault();
    zone.classList.remove("dragover");
    const f = e.dataTransfer.files[0];
    if (f) { input.files = e.dataTransfer.files; fnEl.textContent = f.name; if (onFile) onFile(f); }
  });
  input.addEventListener("change", () => {
    if (input.files[0]) { fnEl.textContent = input.files[0].name; if (onFile) onFile(input.files[0]); }
  });
}

setupDropZone("upload-dropzone", "upload-file", "upload-filename", async file => {
  $("sha-preview").classList.remove("hidden");
  $("sha-preview-val").textContent = "Computing…";
  $("sha-preview-val").textContent = await computeSHA256(file);
});

setupDropZone("verify-dropzone", "verify-file", "verify-filename", async file => {
  $("verify-sha-preview").classList.remove("hidden");
  $("verify-sha-val").textContent = "Computing…";
  $("verify-sha-val").textContent = await computeSHA256(file);
});

setupDropZone("tl-dropzone", "tl-file", "tl-filename");

// ── Navigation ─────────────────────────────────────────────────
document.querySelectorAll(".nav-tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".nav-tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".screen").forEach(s => s.classList.remove("active"));
    tab.classList.add("active");
    $(`screen-${tab.dataset.screen}`).classList.add("active");

    const s = tab.dataset.screen;
    if (s === "register")  loadUsers();
    if (s === "upload")    { loadUsersInto("upload-actor"); loadFiles(); }
    if (s === "timeline")  loadUsersInto("tl-actor");
    if (s === "verify")    {
      loadFilesInto("verify-file-select");
      if (activeFileId) $("verify-file-id").value = activeFileId;
    }
  });
});

// ── Stats (hero counter) ───────────────────────────────────────
async function loadStats() {
  try {
    const d = await fetch(`${API}/stats`).then(r => r.json());
    $("stat-files").textContent       = d.total_files;
    $("stat-records").textContent     = d.total_records;
    $("stat-custodians").textContent  = d.total_custodians;
  } catch {}
}

// ── Hero hash ticker ───────────────────────────────────────────
function initTicker() {
  const el = $("hero-ticker");
  if (!el) return;
  const hex = "0123456789abcdef";
  const rnd = n => Array.from({ length: n }, () => hex[Math.floor(Math.random() * 16)]).join("");
  const seg = Array.from({ length: 10 }, () => `SHA-256: ${rnd(64)}`).join("   ·   ");
  // Duplicate for seamless loop
  el.textContent = seg + "   ·   " + seg;
}

// ── Demo quickfill ─────────────────────────────────────────────
$("btn-quick-demo").addEventListener("click", async () => {
  setLoading("btn-quick-demo", true);
  try {
    const existing = await fetch(`${API}/users`).then(r => r.json()).catch(() => []);
    const existingNames = existing.map(u => u.name);
    const toCreate = ["Reporter", "Editor"].filter(n => !existingNames.includes(n));

    if (toCreate.length === 0) {
      toast("Reporter & Editor already exist!", "info");
    } else {
      for (const name of toCreate) {
        await fetch(`${API}/users/register`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ name })
        });
      }
      toast(`✅ Created: ${toCreate.join(", ")} — now upload a file!`, "success", 4000);
    }
    await loadStats();
    document.querySelector('[data-screen="upload"]').click();
  } catch (e) {
    toast(`Cannot reach backend: ${e.message}`, "error");
  } finally {
    setLoading("btn-quick-demo", false);
  }
});

// ══════════════════════════════════════════════════════════════
// SCREEN 1 — REGISTER
// ══════════════════════════════════════════════════════════════
async function loadUsers() {
  const el = $("users-list");
  el.innerHTML = `<p class="muted">Loading…</p>`;
  try {
    const users = await fetch(`${API}/users`).then(r => r.json());
    if (!users.length) {
      el.innerHTML = `<p class="muted">No custodians yet — register one above.</p>`;
      return;
    }
    el.innerHTML = users.map(u => `
      <div class="user-chip ${activeUser?.user_id === u.id ? "selected" : ""}"
           onclick="selectUser('${u.id}','${u.name}')" data-uid="${u.id}">
        <div>
          <div class="user-chip-name">👤 ${u.name}</div>
          <div class="user-chip-id">${u.id}</div>
        </div>
        <span style="font-size:11px;color:var(--vt-muted)">Click to use →</span>
      </div>
    `).join("");
  } catch {
    el.innerHTML = `<p class="muted" style="color:var(--vt-red)">Cannot reach backend — is the server running?</p>`;
  }
}

function selectUser(id, name) {
  activeUser = { user_id: id, name };
  $("nav-user").textContent = `Acting as: ${name}`;
  document.querySelectorAll(".user-chip").forEach(c =>
    c.classList.toggle("selected", c.dataset.uid === id));
  toast(`Active custodian: ${name}`, "info", 2000);
}

$("btn-register").addEventListener("click", async () => {
  const name = $("reg-name").value.trim();
  if (!name) { showResult("reg-result", "Please enter a custodian name.", true); return; }
  setLoading("btn-register", true);
  try {
    const r    = await fetch(`${API}/users/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name })
    });
    const data = await r.json();
    if (data.error) { showResult("reg-result", data.error, true); return; }

    showResult("reg-result", { "Custodian": data.name, "User ID": data.user_id });

    // Show public key if returned
    if (data.public_key) {
      $("pk-val-text").textContent = data.public_key;
      $("pk-display").classList.remove("hidden");
    }

    selectUser(data.user_id, data.name);
    $("reg-name").value = "";
    loadUsers();
    loadStats();
    toast(`Identity created for ${data.name}`, "success");
  } catch (e) {
    showResult("reg-result", `Network error: ${e.message}`, true);
  } finally {
    setLoading("btn-register", false);
  }
});

$("btn-refresh-users").addEventListener("click", loadUsers);

// ══════════════════════════════════════════════════════════════
// SCREEN 2 — UPLOAD
// ══════════════════════════════════════════════════════════════
async function loadUsersInto(selectId) {
  const sel = $(selectId);
  if (!sel) return;
  sel.innerHTML = `<option value="">— select —</option>`;
  try {
    const users = await fetch(`${API}/users`).then(r => r.json());
    users.forEach(u => {
      const opt = document.createElement("option");
      opt.value = u.id;
      opt.textContent = u.name;
      if (activeUser?.user_id === u.id) opt.selected = true;
      sel.appendChild(opt);
    });
  } catch {}
}

async function loadFiles() {
  const el = $("files-list");
  el.innerHTML = `<p class="muted">Loading…</p>`;
  try {
    const files = await fetch(`${API}/files`).then(r => r.json());
    if (!files.length) { el.innerHTML = `<p class="muted">No files registered yet.</p>`; return; }
    el.innerHTML = files.map(f => `
      <div class="file-chip" onclick="useFileId('${f.id}')">
        <span class="file-chip-icon">${fileIcon(f.original_filename)}</span>
        <div style="flex:1;min-width:0">
          <div class="file-chip-name">${f.original_filename}</div>
          <div class="file-chip-id">${f.id}</div>
        </div>
        <span style="font-size:11px;color:var(--vt-muted);flex-shrink:0">Use →</span>
      </div>
    `).join("");
  } catch {
    el.innerHTML = `<p class="muted" style="color:var(--vt-red)">Cannot reach backend.</p>`;
  }
}

async function loadFilesInto(selectId) {
  const sel = $(selectId);
  if (!sel) return;
  sel.innerHTML = `<option value="">— select or paste ID below —</option>`;
  try {
    const files = await fetch(`${API}/files`).then(r => r.json());
    files.forEach(f => {
      const opt = document.createElement("option");
      opt.value = f.id;
      opt.textContent = `${fileIcon(f.original_filename)} ${f.original_filename} (${f.id.slice(0, 8)}…)`;
      if (activeFileId === f.id) opt.selected = true;
      sel.appendChild(opt);
    });
  } catch {}
}

function useFileId(id) {
  activeFileId = id;
  $("tl-file-id").value    = id;
  $("verify-file-id").value = id;
  document.querySelector('[data-screen="timeline"]').click();
  toast("File selected — loading timeline…", "info", 2000);
}

$("verify-file-select").addEventListener("change", () => {
  const val = $("verify-file-select").value;
  if (val) { $("verify-file-id").value = val; activeFileId = val; }
});

$("btn-upload").addEventListener("click", async () => {
  const actorId = $("upload-actor").value;
  const file    = $("upload-file").files[0];
  if (!actorId || !file) {
    showResult("upload-result", "Select a custodian and a file first.", true);
    return;
  }
  setLoading("btn-upload", true);
  const fd = new FormData();
  fd.append("actor_id", actorId);
  fd.append("file", file);
  try {
    const data = await fetch(`${API}/files/upload`, { method: "POST", body: fd }).then(r => r.json());
    if (data.error) { showResult("upload-result", data.error, true); return; }
    showResult("upload-result", { "File ID": data.file_id, "CREATE Record Hash": data.record_hash });
    activeFileId = data.file_id;
    $("tl-file-id").value    = data.file_id;
    $("verify-file-id").value = data.file_id;
    loadFiles();
    loadStats();
    toast(`File registered — CREATE record signed!`, "success");
  } catch (e) {
    showResult("upload-result", `Network error: ${e.message}`, true);
  } finally {
    setLoading("btn-upload", false);
  }
});

$("btn-refresh-files").addEventListener("click", loadFiles);

// ══════════════════════════════════════════════════════════════
// SCREEN 3 — TIMELINE
// ══════════════════════════════════════════════════════════════
$("btn-load-history").addEventListener("click", () => {
  const fileId = $("tl-file-id").value.trim();
  if (!fileId) { toast("Please enter a File ID.", "error"); return; }
  activeFileId = fileId;
  $("verify-file-id").value = fileId;
  loadHistory(fileId);
});

async function loadHistory(fileId) {
  const container = $("timeline-container");
  const statsBar  = $("tl-stats");
  container.innerHTML = `<p class="muted" style="margin:16px 0">Loading chain history…</p>`;
  statsBar.classList.add("hidden");

  try {
    const hops = await fetch(`${API}/files/${fileId}/history`).then(r => r.json());
    if (!hops.length) {
      container.innerHTML = `<p class="muted" style="margin:16px 0">No records found for this File ID.</p>`;
      return;
    }

    // Stats bar
    const uniqueActors = new Set(hops.map(h => h.actor_id)).size;
    const last = hops[hops.length - 1];
    $("tl-stat-hops").textContent   = hops.length;
    $("tl-stat-actors").textContent = uniqueActors;
    $("tl-stat-last").textContent   = `${last.action_type} by ${last.actor_name || last.actor_id}`;
    statsBar.classList.remove("hidden");

    container.innerHTML = hops.map((h, i) => {
      const prevHash    = i > 0 ? hops[i - 1].file_content_hash : null;
      const changed     = prevHash !== null && h.file_content_hash !== prevHash;
      const deltaClass  = prevHash === null ? "" : (changed ? "changed" : "same");
      const deltaLabel  = prevHash === null ? "" : (changed ? "CONTENT CHANGED" : "CONTENT SAME");
      const safeHash    = h.file_content_hash.replace(/'/g, "");
      const safeRec     = h.record_hash.replace(/'/g, "");
      const safeSig     = h.signature.replace(/'/g, "");

      return `
        <div class="timeline-hop" style="animation-delay:${i * 0.07}s">
          <div class="hop-header">
            <span class="hop-number">#${String(i + 1).padStart(2, "0")}</span>
            <span class="hop-action ${h.action_type}">${h.action_type}</span>
            <span class="hop-actor">👤 ${h.actor_name || h.actor_id}</span>
            ${deltaLabel ? `<span class="hop-delta ${deltaClass}">${deltaLabel}</span>` : ""}
            <span class="hop-time">${fmtTime(h.timestamp)}</span>
          </div>
          <div class="hop-fields">
            <div class="hop-field">
              <span class="hop-field-label">Content Hash</span>
              <span class="hop-field-val">${h.file_content_hash}
                <button class="btn-copy" onclick="copyText('${safeHash}',this)">⎘</button>
              </span>
            </div>
            <div class="hop-field">
              <span class="hop-field-label">Record Hash</span>
              <span class="hop-field-val">${h.record_hash}
                <button class="btn-copy" onclick="copyText('${safeRec}',this)">⎘</button>
              </span>
            </div>
            <div class="hop-field">
              <span class="hop-field-label">Prev Hash</span>
              <span class="hop-field-val">${
                h.prev_record_hash
                  ? h.prev_record_hash
                  : '<em style="color:var(--vt-muted)">genesis — none</em>'
              }</span>
            </div>
            ${h.declared_transformation ? `
            <div class="hop-field">
              <span class="hop-field-label">Transformation</span>
              <span class="hop-field-val" style="color:var(--vt-yellow)">${h.declared_transformation}</span>
            </div>` : ""}
            <div class="hop-field">
              <span class="hop-field-label">Signature</span>
              <span class="hop-field-val sig-valid">✅ ${h.signature.slice(0, 32)}…
                <button class="btn-copy" onclick="copyText('${safeSig}',this)">⎘ full</button>
              </span>
            </div>
          </div>
        </div>
      `;
    }).join("");
  } catch (e) {
    container.innerHTML = `<p class="muted" style="color:var(--vt-red)">Error: ${e.message}</p>`;
  }
}

$("btn-action").addEventListener("click", async () => {
  const fileId     = $("tl-file-id").value.trim();
  const actorId    = $("tl-actor").value;
  const actionType = $("tl-action-type").value;
  const declared   = $("tl-transform").value.trim();
  const file       = $("tl-file").files[0];

  if (!fileId || !actorId) {
    showResult("action-result", "File ID and custodian are both required.", true);
    return;
  }
  if (actionType === "MODIFY" && !file) {
    showResult("action-result", "MODIFY requires uploading the new file version.", true);
    return;
  }

  setLoading("btn-action", true);
  const fd = new FormData();
  fd.append("actor_id",   actorId);
  fd.append("action_type", actionType);
  if (declared) fd.append("declared_transformation", declared);
  if (file)    fd.append("file", file);

  try {
    const data = await fetch(`${API}/files/${fileId}/action`, { method: "POST", body: fd }).then(r => r.json());
    if (data.error) { showResult("action-result", data.error, true); return; }
    showResult("action-result", { "New Record Hash": data.record_hash });
    loadHistory(fileId);
    loadStats();
    toast(`${actionType} record added and signed!`, "success");
  } catch (e) {
    showResult("action-result", `Network error: ${e.message}`, true);
  } finally {
    setLoading("btn-action", false);
  }
});

// ══════════════════════════════════════════════════════════════
// SCREEN 4 — VERIFY
// ══════════════════════════════════════════════════════════════
$("btn-verify").addEventListener("click", async () => {
  const fileId = $("verify-file-id").value.trim();
  const file   = $("verify-file").files[0];
  if (!fileId) { toast("Please enter or select a File ID.", "error"); return; }
  if (!file)   { toast("Please select a file to verify.", "error"); return; }

  // Hide previous results
  ["verdict-wrap", "hash-compare", "verify-chain-panel", "ela-wrap"].forEach(id =>
    $(id).classList.add("hidden"));

  setLoading("btn-verify", true);
  const fd = new FormData();
  fd.append("file", file);

  try {
    const result = await fetch(`${API}/files/${fileId}/verify`, {
      method: "POST", body: fd
    }).then(r => r.json());

    renderVerdict(result);
    loadVerifyChain(fileId, result);

    // ELA for images
    if (file.type.startsWith("image/")) {
      const fd2 = new FormData();
      fd2.append("file", $("verify-file").files[0]);
      fetchELA(fileId, fd2);
    }
  } catch (e) {
    $("verdict-wrap").classList.remove("hidden");
    $("verdict-badge").textContent = `⚠️ Network error: ${e.message}`;
    $("verdict-badge").className = "badge badge-unknown";
    toast(`Network error: ${e.message}`, "error");
  } finally {
    setLoading("btn-verify", false);
  }
});

function renderVerdict(result) {
  const badge  = $("verdict-badge");
  const detail = $("verdict-detail");
  $("verdict-wrap").classList.remove("hidden");
  badge.className = "badge";

  if (result.status === "VERIFIED") {
    const n = result.hops;
    badge.textContent = `✅ VERIFIED — ${n} custody hop${n > 1 ? "s" : ""} confirmed`;
    badge.classList.add("badge-verified");
    const actors = result.unique_actors?.map(a => a.name).join(" → ") || "";
    detail.textContent =
      `The complete chain of custody is cryptographically intact. ` +
      `Every Ed25519 signature is valid, every hash-link is unbroken, ` +
      `and the current file matches the last recorded ledger state.` +
      (actors ? ` Chain: ${actors}` : "");

  } else if (result.status === "TAMPERED") {
    const hop    = result.broken_at + 1;
    const actor  = result.actor_name || result.actor_id || "unknown";
    badge.textContent = `🚨 TAMPERED — broken at hop #${String(hop).padStart(2, "0")}`;
    badge.classList.add("badge-tampered");
    detail.textContent = `Reason: ${result.reason}. Actor at broken hop: ${actor}.`;

    // Hash comparison panel for content-mismatch case
    if (result.expected_hash && result.current_hash) {
      $("hash-expected").textContent = result.expected_hash;
      $("hash-current").textContent  = result.current_hash;
      $("hash-compare").classList.remove("hidden");
    }
    toast(`🚨 TAMPERED — chain broken at hop #${hop} (${actor})`, "error", 6000);

  } else {
    badge.textContent = `⚠️ UNKNOWN PROVENANCE`;
    badge.classList.add("badge-unknown");
    detail.textContent = result.reason || "No custody history found for this File ID.";
    toast("Unknown provenance — no records found.", "error");
  }
}

async function loadVerifyChain(fileId, verifyResult) {
  try {
    const hops = await fetch(`${API}/files/${fileId}/history`).then(r => r.json());
    if (!hops.length) return;

    const brokenAt  = verifyResult.broken_at ?? null;
    const isVerified = verifyResult.status === "VERIFIED";
    const isTampered = verifyResult.status === "TAMPERED";

    $("verify-chain-panel").classList.remove("hidden");
    $("verify-chain-table").innerHTML = hops.map((h, i) => {
      let rowClass = "vct-row";
      let statusHtml;

      if (isVerified) {
        statusHtml = `<span style="color:var(--vt-green)">✅ Valid</span>`;
      } else if (isTampered) {
        if (brokenAt === null || i < brokenAt) {
          statusHtml = `<span style="color:var(--vt-green)">✅ Valid</span>`;
        } else if (i === brokenAt) {
          rowClass += " vct-broken";
          statusHtml = `<span style="color:var(--vt-red)">🔴 BROKEN</span>`;
        } else {
          rowClass += " vct-after";
          statusHtml = `<span style="color:var(--vt-muted)">⚪ —</span>`;
        }
      } else {
        statusHtml = `<span style="color:var(--vt-muted)">?</span>`;
      }

      const isBreak = isTampered && i === brokenAt;
      return `
        <div class="${rowClass}">
          <span class="vct-num">#${String(i + 1).padStart(2, "0")}</span>
          <span class="vct-action ${h.action_type}">${h.action_type}</span>
          <span class="vct-actor">👤 ${h.actor_name || h.actor_id}</span>
          <span class="vct-hash" title="${h.file_content_hash}">${h.file_content_hash.slice(0, 10)}…${h.file_content_hash.slice(-6)}</span>
          <span class="vct-status">${statusHtml}</span>
          ${isBreak ? `<div class="vct-reason">↑ ${verifyResult.reason}</div>` : ""}
        </div>
      `;
    }).join("");
  } catch {}
}

async function fetchELA(fileId, fd) {
  try {
    const r = await fetch(`${API}/files/${fileId}/ela`, { method: "POST", body: fd });
    if (r.ok) {
      const blob = await r.blob();
      $("ela-img").src = URL.createObjectURL(blob);
      $("ela-wrap").classList.remove("hidden");
    }
  } catch {}
}

// ══════════════════════════════════════════════════════════════
// INIT
// ══════════════════════════════════════════════════════════════
window.addEventListener("load", () => {
  loadUsers();
  loadStats();
  initTicker();
});
