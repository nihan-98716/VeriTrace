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
  return new Date(ts * 1000).toLocaleString("en-IN", {
    timeZone: "Asia/Kolkata",
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: true
  }) + " IST";
}

function fmtIST(dateInput) {
  if (!dateInput) return "";
  try {
    const d = new Date(dateInput);
    if (isNaN(d.getTime())) return dateInput;
    return d.toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata",
      year: "numeric", month: "short", day: "numeric",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
      hour12: true
    }) + " IST";
  } catch {
    return dateInput;
  }
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

function escHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
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

function clearVerifyPanels() {
  ["verdict-wrap", "hash-compare", "verify-chain-panel", "ela-wrap", "semantic-wrap", "freq-wrap"].forEach(id => {
    const el = $(id);
    if (el) el.classList.add("hidden");
  });
  if ($("verdict-subject")) $("verdict-subject").innerHTML = "";
  if ($("ela-file-meta")) $("ela-file-meta").textContent = "";
  if ($("freq-file-meta")) $("freq-file-meta").textContent = "";
  if ($("ela-img")) $("ela-img").src = "";
  if ($("fft-img")) $("fft-img").src = "";
  if ($("dct-img")) $("dct-img").src = "";
  if ($("fft-summary")) $("fft-summary").textContent = "";
  if ($("dct-summary")) $("dct-summary").textContent = "";
  if ($("semantic-summary")) $("semantic-summary").textContent = "";
  if ($("semantic-details")) $("semantic-details").innerHTML = "";
  if ($("verdict-badge")) $("verdict-badge").textContent = "";
  if ($("verdict-detail")) $("verdict-detail").innerHTML = "";
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
  if ($("btn-clear-verify-file")) $("btn-clear-verify-file").classList.remove("hidden");
});

if ($("btn-clear-verify-file")) {
  $("btn-clear-verify-file").addEventListener("click", (e) => {
    e.stopPropagation();
    $("verify-file").value = "";
    $("verify-filename").textContent = "";
    $("verify-sha-preview").classList.add("hidden");
    $("btn-clear-verify-file").classList.add("hidden");
    clearVerifyPanels();
    toast("External file cleared. Auto-verifying registered ledger file directly.", "info", 2500);
  });
}

setupDropZone("tl-dropzone", "tl-file", "tl-filename");

function updateTimelineActionTypeUI() {
  const select = $("tl-action-type");
  if (!select) return;
  const type = select.value;
  const dropzone = $("tl-dropzone");
  const notice = $("tl-transfer-notice");
  const prompt = $("tl-dropzone-prompt");
  if (type === "TRANSFER") {
    if (dropzone) dropzone.classList.add("hidden");
    if (notice) notice.classList.remove("hidden");
    if ($("tl-file")) $("tl-file").value = "";
    if ($("tl-filename")) $("tl-filename").textContent = "";
  } else if (type === "MODIFY") {
    if (dropzone) dropzone.classList.remove("hidden");
    if (notice) notice.classList.add("hidden");
    if (prompt) prompt.textContent = "Drop new / updated file version here (required for MODIFY)";
  } else if (type === "REDACT") {
    if (dropzone) dropzone.classList.remove("hidden");
    if (notice) notice.classList.add("hidden");
    if (prompt) prompt.textContent = "Drop redacted document here (required for REDACT)";
  }
}
if ($("tl-action-type")) $("tl-action-type").addEventListener("change", updateTimelineActionTypeUI);

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
    if (s === "timeline")  { loadUsersInto("tl-actor"); updateTimelineActionTypeUI(); }
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

// ── Reset All & Redo ──────────────────────────────────────────
async function handleResetSystem() {
  const confirmed = confirm("Are you sure you want to reset all data?\n\nThis will clear all registered custodians, uploaded files, and cryptographic ledger records so you can redo from scratch.");
  if (!confirmed) return;

  try {
    const res = await fetch(`${API}/reset`, { method: "POST" }).then(r => r.json());
    if (res.success) {
      activeUser = null;
      activeFileId = null;
      $("nav-user").textContent = "No user selected";

      // Clear inputs and previews across all screens
      if ($("reg-name")) $("reg-name").value = "";
      if ($("reg-result")) $("reg-result").classList.add("hidden");
      if ($("pk-display")) $("pk-display").classList.add("hidden");

      if ($("upload-file")) $("upload-file").value = "";
      if ($("upload-filename")) $("upload-filename").textContent = "";
      if ($("upload-sha-preview")) $("upload-sha-preview").classList.add("hidden");
      if ($("upload-result")) $("upload-result").classList.add("hidden");

      if ($("tl-file-id")) $("tl-file-id").value = "";
      if ($("tl-transform")) $("tl-transform").value = "";
      if ($("tl-file")) $("tl-file").value = "";
      if ($("tl-filename")) $("tl-filename").textContent = "";
      if ($("action-result")) $("action-result").classList.add("hidden");
      if ($("tl-stats")) $("tl-stats").classList.add("hidden");
      if ($("timeline-container")) $("timeline-container").innerHTML = "";

      if ($("verify-file-id")) $("verify-file-id").value = "";
      if ($("verify-file")) $("verify-file").value = "";
      if ($("verify-filename")) $("verify-filename").textContent = "";
      if ($("verify-sha-preview")) $("verify-sha-preview").classList.add("hidden");
      if ($("btn-clear-verify-file")) $("btn-clear-verify-file").classList.add("hidden");

      // Hide all result panels and clear image elements
      clearVerifyPanels();
      updateTimelineActionTypeUI();

      await loadStats();
      await loadUsers();
      await loadUploadedFiles();

      toast("🔄 System reset! All files and records cleared. Ready to redo.", "success", 4000);
      document.querySelector('[data-screen="register"]').click();
    } else {
      toast("Reset failed: " + (res.error || "Unknown error"), "error");
    }
  } catch (e) {
    toast(`Cannot reset: ${e.message}`, "error");
  }
}

if ($("btn-reset-demo")) $("btn-reset-demo").addEventListener("click", handleResetSystem);
if ($("btn-nav-reset")) $("btn-nav-reset").addEventListener("click", handleResetSystem);

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
        <div style="flex:1;min-width:0">
          <div class="user-chip-name">👤 ${u.name}</div>
          <div class="user-chip-id">${u.id}</div>
          ${u.public_key ? `<div style="font-size:10px;color:var(--vt-cyan);font-family:var(--font-mono);margin-top:2px" title="${u.public_key}">🔑 Public Key: ${u.public_key.slice(0, 16)}…</div>` : ""}
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
      let label = `${fileIcon(f.original_filename)} ${f.original_filename}`;
      if (f.latest_resolved_filename && f.latest_resolved_filename !== f.original_filename) {
        label += ` → ${f.latest_resolved_filename} [MODIFIED]`;
      }
      label += ` (${f.id.slice(0, 8)}…)`;
      opt.textContent = label;
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
  if (val) {
    $("verify-file-id").value = val;
    activeFileId = val;
    clearVerifyPanels();
    if ($("verify-file")) $("verify-file").value = "";
    if ($("verify-filename")) $("verify-filename").textContent = "";
    if ($("verify-sha-preview")) $("verify-sha-preview").classList.add("hidden");
    if ($("btn-clear-verify-file")) $("btn-clear-verify-file").classList.add("hidden");
  }
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
            ${(h.tsa_certified_ist || h.tsa_certified_utc) ? `
            <div class="hop-field">
              <span class="hop-field-label">RFC 3161 TSA</span>
              <span class="hop-field-val" style="color:var(--vt-cyan)">
                ⏱️ ${h.tsa_certified_ist || fmtIST(h.tsa_certified_utc)} · <span style="font-size:11px;color:#a5f3fc">${(h.tsa_cert_info && (h.tsa_cert_info.tsa_common_name || h.tsa_cert_info.tsa_org)) || "TSA Signer"} (Cert: ${(h.tsa_cert_info && h.tsa_cert_info.cert_serial_hex) ? h.tsa_cert_info.cert_serial_hex.slice(0, 10) + '…' : 'Verified'})</span>
              </span>
            </div>` : ""}
            <div class="hop-field">
              <span class="hop-field-label">Record Signature</span>
              <span class="hop-field-val sig-valid">✅ ${h.signature.slice(0, 32)}…
                <button class="btn-copy" onclick="copyText('${safeSig}',this)">⎘ full</button>
              </span>
            </div>
            ${h.actor_public_key ? `
            <div class="hop-field">
              <span class="hop-field-label">Signer Public Key</span>
              <span class="hop-field-val" style="color:var(--vt-cyan);font-family:var(--font-mono)">
                🔑 ${h.actor_public_key.slice(0, 32)}…
                <button class="btn-copy" onclick="copyText('${h.actor_public_key.replace(/'/g, "")}',this)">⎘ full</button>
              </span>
            </div>` : ""}
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
  if (actionType === "REDACT" && !file) {
    showResult("action-result", "REDACT requires uploading the redacted document.", true);
    return;
  }

  setLoading("btn-action", true);
  const fd = new FormData();
  fd.append("actor_id",   actorId);
  fd.append("action_type", actionType);
  if (declared) fd.append("declared_transformation", declared);
  // Never attach file for TRANSFER: TRANSFER preserves the existing asset content
  if (actionType !== "TRANSFER" && file) fd.append("file", file);

  try {
    const endpoint = actionType === "REDACT" ? `${API}/files/${fileId}/redact` : `${API}/files/${fileId}/action`;
    const data = await fetch(endpoint, { method: "POST", body: fd }).then(r => r.json());
    if (data.error) { showResult("action-result", data.error, true); return; }
    showResult("action-result", { "New Record Hash": data.record_hash, "Status": data.status || "SIGNED" });

    // Clear dropzone inputs so they do not pollute subsequent actions
    if ($("tl-file")) $("tl-file").value = "";
    if ($("tl-filename")) $("tl-filename").textContent = "";
    if ($("tl-transform")) $("tl-transform").value = "";
    updateTimelineActionTypeUI();

    loadHistory(fileId);
    loadStats();
    toast(`${actionType} record added and cryptographically certified!`, "success");
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

  // Clear previous forensic images and hide previous results immediately
  clearVerifyPanels();

  setLoading("btn-verify", true);
  const fd = new FormData();
  if (file) {
    fd.append("file", file);
  }

  try {
    const result = await fetch(`${API}/files/${fileId}/verify`, {
      method: "POST", body: fd
    }).then(r => r.json());

    if (result.error) {
      toast(result.error, "error");
      return;
    }

    renderVerdict(result);
    loadVerifyChain(fileId, result);

    // Strict Modality Isolation: ELA and Frequency analysis ONLY for image files
    const isImg = Boolean(result.is_image);
    if (isImg) {
      if ($("semantic-wrap")) $("semantic-wrap").classList.add("hidden");
      const fd2 = new FormData();
      if (file) fd2.append("file", file);
      fetchELA(fileId, fd2);
      fetchFrequency(fileId, fd2);
    } else {
      if ($("ela-wrap")) $("ela-wrap").classList.add("hidden");
      if ($("freq-wrap")) $("freq-wrap").classList.add("hidden");
      if ($("ela-img")) $("ela-img").src = "";
      if ($("fft-img")) $("fft-img").src = "";
      if ($("dct-img")) $("dct-img").src = "";
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

  if ($("verdict-subject")) {
    const vName = result.verified_filename || "current asset";
    const vHash = result.current_hash ? `${result.current_hash.slice(0, 10)}…${result.current_hash.slice(-6)}` : "";
    $("verdict-subject").innerHTML = `📁 <strong>Target Evaluated:</strong> <span style="color:#fff">${escHtml(vName)}</span> &nbsp;·&nbsp; <strong>SHA-256:</strong> <code>${vHash}</code>`;
  }

  const isImg = Boolean(result.is_image);
  if (isImg) {
    if ($("semantic-wrap")) $("semantic-wrap").classList.add("hidden");
  } else {
    if ($("ela-wrap")) $("ela-wrap").classList.add("hidden");
    if ($("freq-wrap")) $("freq-wrap").classList.add("hidden");
  }

  if (result.status === "VERIFIED") {
    const n = result.hops;
    badge.textContent = `✅ VERIFIED — ${n} custody hop${n > 1 ? "s" : ""} confirmed`;
    badge.classList.add("badge-verified");
    const actors = result.unique_actors?.map(a => a.name).join(" → ") || "";
    detail.textContent =
      `The complete chain of custody is cryptographically intact. ` +
      `Every signature is valid, every hash-link is unbroken, ` +
      `and the verified file matches the last recorded ledger state.` +
      (actors ? ` Chain: ${actors}` : "");

  } else if (result.status === "VERIFIED_REDACTED") {
    const n = result.hops;
    badge.textContent = `🛡️ VERIFIED (AUTHENTIC REDACTION) — ${n} hop${n > 1 ? "s" : ""} confirmed`;
    badge.classList.add("badge-verified");
    badge.style.backgroundColor = "#2563eb";
    const redactedInfo = result.redacted_segments?.length ? ` Redacted sections: ${result.redacted_segments.join(", ")}.` : "";
    detail.innerHTML =
      `<strong>Zero-Knowledge Redaction Confirmed:</strong> ${result.message || "Authentic redaction verified."}` +
      redactedInfo + ` All unredacted text matches the original certified Merkle root.`;

  } else if (result.status === "TAMPERED") {
    const hop    = (result.broken_at ?? 0) + 1;
    const actor  = result.actor_name || result.actor_id || "unknown";
    if (result.tamper_type === "EXTERNAL_MODIFICATION") {
      badge.textContent = `🚨 TAMPERED — External file alteration (differs from final hop #${String(hop).padStart(2, "0")})`;
    } else if (result.tamper_type === "HISTORICAL_ROLLBACK") {
      badge.textContent = `🚨 TAMPERED — Rollback / Stale Version at hop #${String(hop).padStart(2, "0")}`;
    } else {
      badge.textContent = `🚨 TAMPERED — broken at hop #${String(hop).padStart(2, "0")}`;
    }
    badge.classList.add("badge-tampered");
    
    let segText = "";
    if (!isImg && result.tampered_segments && result.tampered_segments.length > 0) {
      segText = `<br/><strong style="color:var(--vt-red)">🔍 Granular Alteration Localization:</strong><ul style="margin:4px 0 0 18px;text-align:left">${result.tampered_segments.map(s => `<li>${escHtml(s)}</li>`).join("")}</ul>`;
    }
    
    detail.innerHTML = `<strong>Root Cause:</strong> ${escHtml(result.reason)}. <br/><strong>Signer/Custodian at Hop #${hop}:</strong> ${escHtml(actor)}.${segText}`;

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

  // Semantic NLP Assessment Card (strictly for text documents with detected differences)
  if (!isImg && result.semantic_assessment && $("semantic-wrap")) {
    const sem = result.semantic_assessment;
    const sWrap = $("semantic-wrap");
    const sBadge = $("semantic-risk-badge");
    const sSummary = $("semantic-summary");
    const sDetails = $("semantic-details");

    sWrap.classList.remove("hidden");
    sBadge.textContent = `${sem.overall_risk} RISK`;
    if (sem.overall_risk === "CRITICAL") {
      sBadge.className = "badge badge-tampered";
      sWrap.style.borderLeftColor = "var(--vt-red)";
    } else if (sem.overall_risk === "SUBSTANTIVE") {
      sBadge.className = "badge badge-unknown";
      sWrap.style.borderLeftColor = "#f59e0b";
    } else if (sem.overall_risk === "MODERATE") {
      sBadge.className = "badge badge-unknown";
      sWrap.style.borderLeftColor = "#38bdf8";
    } else {
      sBadge.className = "badge badge-verified";
      sWrap.style.borderLeftColor = "#10b981";
    }

    sSummary.textContent = sem.summary;
    if (sem.assessments && sem.assessments.length > 0) {
      sDetails.innerHTML = sem.assessments.map(a => {
        let badgeClass = "badge-verified";
        if (a.risk_level === "CRITICAL") badgeClass = "badge-tampered";
        else if (a.risk_level === "SUBSTANTIVE" || a.risk_level === "MODERATE") badgeClass = "badge-unknown";

        const reasonsHtml = (a.risk_reasons && a.risk_reasons.length > 0)
          ? `<ul style="margin:4px 0 0 16px;color:var(--vt-text);font-size:12px">${a.risk_reasons.map(r => `<li>${escHtml(r)}</li>`).join("")}</ul>`
          : "";

        const origQuoteHtml = a.original_text
          ? `<div style="margin-top:6px;font-size:12px;color:var(--vt-muted)">Original: <span style="color:#f87171;text-decoration:line-through;background:rgba(239,68,68,0.08);padding:2px 5px;border-radius:3px">"${escHtml(a.original_text)}"</span></div>`
          : "";

        const modQuoteHtml = a.tampered_text
          ? `<div style="margin-top:3px;font-size:12px;color:var(--vt-muted)">Tampered: <span style="color:#4ade80;background:rgba(34,197,94,0.08);padding:2px 5px;border-radius:3px">"${escHtml(a.tampered_text)}"</span></div>`
          : "";

        return `
          <div style="margin-top:8px;padding:8px 10px;background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);border-radius:6px">
            <div style="display:flex;justify-content:space-between;align-items:center">
              <span style="font-weight:600;color:var(--vt-text-bright)">${escHtml(a.segment_name || "Text Segment")}</span>
              <span class="badge ${badgeClass}" style="font-size:10px;padding:2px 6px">${a.risk_level}</span>
            </div>
            ${reasonsHtml}
            ${origQuoteHtml}
            ${modQuoteHtml}
          </div>
        `;
      }).join("");
    } else {
      sDetails.innerHTML = `<p class="muted" style="font-size:12px;margin:4px 0">No individual segment anomalies flagged.</p>`;
    }
  }
}

async function loadVerifyChain(fileId, verifyResult) {
  try {
    const hops = await fetch(`${API}/files/${fileId}/history`).then(r => r.json());
    if (!hops.length) return;

    const brokenAt  = verifyResult.broken_at ?? null;
    const isVerified = verifyResult.status === "VERIFIED" || verifyResult.status === "VERIFIED_REDACTED";
    const isTampered = verifyResult.status === "TAMPERED";

    $("verify-chain-panel").classList.remove("hidden");
    $("verify-chain-table").innerHTML = hops.map((h, i) => {
      let rowClass = "vct-row";
      let statusHtml;

      if (isVerified) {
        statusHtml = `<span style="color:var(--vt-green)">✅ Valid in Ledger</span>`;
      } else if (isTampered) {
        if (brokenAt === null || i < brokenAt) {
          statusHtml = `<span style="color:var(--vt-green)">✅ Valid in Ledger</span>`;
        } else if (i === brokenAt) {
          rowClass += " vct-broken";
          if (verifyResult.tamper_type === "EXTERNAL_MODIFICATION") {
            statusHtml = `<span style="color:var(--vt-yellow)">⚠ Modified Outside Chain</span>`;
          } else {
            statusHtml = `<span style="color:var(--vt-red)">🔴 BROKEN</span>`;
          }
        } else {
          rowClass += " vct-after";
          statusHtml = `<span style="color:var(--vt-muted)">⚪ —</span>`;
        }
      } else {
        statusHtml = `<span style="color:var(--vt-muted)">?</span>`;
      }

      const isBreak = isTampered && i === brokenAt;
      
      // Detailed RFC 3161 TSA and Certificate verification badge
      let tsaBadge = "";
      if (h.tsa_certified_utc || h.tsa_certified_ist) {
        const cert = h.tsa_cert_info || {};
        const tsaName = cert.tsa_common_name || cert.tsa_org || "RFC 3161 TSA";
        const certSerial = cert.cert_serial_hex ? ` (Cert: ${cert.cert_serial_hex.slice(0, 8)}…)` : "";
        const timeDisplay = h.tsa_certified_ist || fmtIST(h.tsa_certified_utc);
        tsaBadge = `
          <div style="font-size:11px;color:var(--vt-cyan);margin-top:2px" title="TSA Cert Serial: ${cert.cert_serial_hex || 'N/A'}, Issuer: ${cert.issuer_org || cert.issuer_common_name || 'Root CA'}">
            ⏱️ <strong>TSA Certified:</strong> ${timeDisplay} · <span style="color:#a5f3fc">${tsaName}${certSerial}</span>
          </div>`;
      }

      return `
        <div class="${rowClass}">
          <span class="vct-num">#${String(i + 1).padStart(2, "0")}</span>
          <span class="vct-action ${h.action_type}">${h.action_type}</span>
          <span class="vct-actor">👤 ${h.actor_name || h.actor_id} ${tsaBadge}</span>
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
      const evalName = r.headers.get("X-Evaluated-Filename");
      const evalHash = r.headers.get("X-Evaluated-Hash");
      if ($("ela-file-meta") && evalName) {
        const hShort = evalHash ? `${evalHash.slice(0, 10)}…${evalHash.slice(-6)}` : "";
        $("ela-file-meta").textContent = `Target Analyzed: ${evalName} (${hShort})`;
      }
      const blob = await r.blob();
      $("ela-img").src = URL.createObjectURL(blob);
      $("ela-wrap").classList.remove("hidden");
    }
  } catch {}
}

async function fetchFrequency(fileId, fd) {
  try {
    const res = await fetch(`${API}/files/${fileId}/frequency_analysis`, { method: "POST", body: fd }).then(r => r.json());
    if (res.success && $("freq-wrap")) {
      $("freq-wrap").classList.remove("hidden");
      $("fft-img").src = res.fft_image_data;
      $("dct-img").src = res.dct_image_data;
      $("fft-summary").textContent = res.fft_summary;
      $("dct-summary").textContent = res.dct_summary;

      if ($("freq-file-meta") && res.evaluated_filename) {
        const hashShort = res.evaluated_hash ? `${res.evaluated_hash.slice(0, 10)}…${res.evaluated_hash.slice(-6)}` : "";
        const refShort = res.reference_hash ? ` · Ref Genesis: ${res.reference_hash.slice(0, 10)}…` : "";
        const tag = res.is_modified_from_genesis ? " [TAMPERED/MODIFIED]" : " [GENESIS]";
        $("freq-file-meta").textContent = `Target Analyzed: ${res.evaluated_filename} (${hashShort})${tag}${refShort}`;
      }
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
  updateTimelineActionTypeUI();
});
