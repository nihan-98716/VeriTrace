const API = "http://localhost:5000/api";

// ── State ──────────────────────────────────────────────────────
let activeUser = null; // { user_id, name }
let activeFileId = null;

// ── Navigation ─────────────────────────────────────────────────
document.querySelectorAll(".nav-tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".nav-tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".screen").forEach(s => s.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById(`screen-${tab.dataset.screen}`).classList.add("active");
    if (tab.dataset.screen === "register") loadUsers();
    if (tab.dataset.screen === "upload") { loadUsersInto("upload-actor"); loadFiles(); }
    if (tab.dataset.screen === "timeline") { loadUsersInto("tl-actor"); }
    if (tab.dataset.screen === "verify") loadFilesInto("verify-file-id");
  });
});

// ── Utility ────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
function showResult(elId, data, isError = false) {
  const el = $(elId);
  el.classList.remove("hidden", "error", "success");
  if (typeof data === "object") {
    el.innerHTML = Object.entries(data)
      .map(([k,v]) => `<div class="result-label">${k}</div><div class="result-value">${v}</div>`)
      .join("");
  } else {
    el.textContent = data;
  }
  if (isError) el.classList.add("error"); else el.classList.add("success");
}

function fmtTime(ts) {
  return new Date(ts * 1000).toLocaleString();
}

// ── File drop zones ────────────────────────────────────────────
function setupDropZone(zoneId, inputId, filenameId) {
  const zone = $(zoneId), input = $(inputId), fnEl = $(filenameId);
  zone.addEventListener("dragover", e => { e.preventDefault(); zone.classList.add("dragover"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("dragover"));
  zone.addEventListener("drop", e => {
    e.preventDefault(); zone.classList.remove("dragover");
    if (e.dataTransfer.files[0]) { input.files = e.dataTransfer.files; fnEl.textContent = e.dataTransfer.files[0].name; }
  });
  input.addEventListener("change", () => { if (input.files[0]) fnEl.textContent = input.files[0].name; });
}
setupDropZone("upload-dropzone", "upload-file", "upload-filename");
setupDropZone("verify-dropzone", "verify-file",  "verify-filename");
setupDropZone("tl-dropzone",    "tl-file",       "tl-filename");

// ── Screen 1: Register ─────────────────────────────────────────
async function loadUsers() {
  const el = $("users-list");
  el.innerHTML = `<p class="muted">Loading…</p>`;
  try {
    const r = await fetch(`${API}/users`);
    const users = await r.json();
    if (!users.length) { el.innerHTML = `<p class="muted">No custodians yet.</p>`; return; }
    el.innerHTML = users.map(u => `
      <div class="user-chip ${activeUser?.user_id === u.id ? 'selected' : ''}" 
           onclick="selectUser('${u.id}', '${u.name}')" data-uid="${u.id}">
        <div>
          <div class="user-chip-name">👤 ${u.name}</div>
          <div class="user-chip-id">${u.id}</div>
        </div>
        <span style="font-size:11px;color:var(--muted)">Click to use →</span>
      </div>
    `).join("");
  } catch { el.innerHTML = `<p class="muted" style="color:var(--red)">Cannot reach backend.</p>`; }
}

function selectUser(id, name) {
  activeUser = { user_id: id, name };
  $("nav-user").textContent = `Acting as: ${name}`;
  document.querySelectorAll(".user-chip").forEach(c => {
    c.classList.toggle("selected", c.dataset.uid === id);
  });
}

$("btn-register").addEventListener("click", async () => {
  const name = $("reg-name").value.trim();
  if (!name) { showResult("reg-result", "Please enter a name.", true); return; }
  try {
    const r = await fetch(`${API}/users/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name })
    });
    const data = await r.json();
    showResult("reg-result", { "Custodian": data.name, "User ID": data.user_id });
    selectUser(data.user_id, data.name);
    $("reg-name").value = "";
    loadUsers();
  } catch(e) { showResult("reg-result", `Error: ${e.message}`, true); }
});

$("btn-refresh-users").addEventListener("click", loadUsers);
loadUsers();

// ── Screen 2: Upload ───────────────────────────────────────────
async function loadUsersInto(selectId) {
  const sel = $(selectId);
  sel.innerHTML = `<option value="">— select —</option>`;
  try {
    const r = await fetch(`${API}/users`);
    const users = await r.json();
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
    const r = await fetch(`${API}/files`);
    const files = await r.json();
    if (!files.length) { el.innerHTML = `<p class="muted">No files yet.</p>`; return; }
    el.innerHTML = files.map(f => `
      <div class="file-chip" onclick="useFileId('${f.id}')">
        <span class="file-chip-icon">📄</span>
        <div>
          <div class="file-chip-name">${f.original_filename}</div>
          <div class="file-chip-id">${f.id}</div>
        </div>
      </div>
    `).join("");
  } catch { el.innerHTML = `<p class="muted" style="color:var(--red)">Cannot reach backend.</p>`; }
}

function useFileId(id) {
  activeFileId = id;
  $("tl-file-id").value = id;
  $("verify-file-id").value = id;
  // Switch to timeline
  document.querySelector('[data-screen="timeline"]').click();
}

async function loadFilesInto(inputId) {
  // Just pre-fill if we have an activeFileId
  if (activeFileId) $(inputId).value = activeFileId;
}

$("btn-upload").addEventListener("click", async () => {
  const actorId = $("upload-actor").value;
  const file    = $("upload-file").files[0];
  if (!actorId || !file) { showResult("upload-result", "Select a custodian and a file first.", true); return; }

  const fd = new FormData();
  fd.append("actor_id", actorId);
  fd.append("file", file);

  try {
    const r = await fetch(`${API}/files/upload`, { method: "POST", body: fd });
    const data = await r.json();
    if (data.error) { showResult("upload-result", data.error, true); return; }
    showResult("upload-result", { "File ID": data.file_id, "Record Hash (CREATE)": data.record_hash });
    activeFileId = data.file_id;
    $("tl-file-id").value = data.file_id;
    $("verify-file-id").value = data.file_id;
    loadFiles();
  } catch(e) { showResult("upload-result", `Error: ${e.message}`, true); }
});

$("btn-refresh-files").addEventListener("click", loadFiles);

// ── Screen 3: Timeline ─────────────────────────────────────────
$("btn-load-history").addEventListener("click", () => {
  const fileId = $("tl-file-id").value.trim();
  if (!fileId) return;
  activeFileId = fileId;
  loadHistory(fileId);
});

async function loadHistory(fileId) {
  const container = $("timeline-container");
  container.innerHTML = `<p class="muted" style="margin:16px 0">Loading history…</p>`;
  try {
    const r = await fetch(`${API}/files/${fileId}/history`);
    const hops = await r.json();
    if (!hops.length) { container.innerHTML = `<p class="muted" style="margin:16px 0">No records found for this file ID.</p>`; return; }
    container.innerHTML = hops.map((h, i) => `
      <div class="timeline-hop">
        <div class="hop-header">
          <span class="hop-action ${h.action_type}">${h.action_type}</span>
          <span class="hop-actor">👤 ${h.actor_name || h.actor_id}</span>
          <span class="hop-time">${fmtTime(h.timestamp)}</span>
        </div>
        <div class="hop-fields">
          <div class="hop-field">
            <span class="hop-field-label">Content Hash</span>
            <span class="hop-field-val">${h.file_content_hash}</span>
          </div>
          <div class="hop-field">
            <span class="hop-field-label">Record Hash</span>
            <span class="hop-field-val">${h.record_hash}</span>
          </div>
          <div class="hop-field">
            <span class="hop-field-label">Prev Hash</span>
            <span class="hop-field-val">${h.prev_record_hash || '<em style="color:var(--muted)">genesis (none)</em>'}</span>
          </div>
          ${h.declared_transformation ? `<div class="hop-field">
            <span class="hop-field-label">Transformation</span>
            <span class="hop-field-val">${h.declared_transformation}</span>
          </div>` : ''}
          <div class="hop-field">
            <span class="hop-field-label">Signature</span>
            <span class="hop-field-val sig-valid">✅ ${h.signature.slice(0,32)}…</span>
          </div>
        </div>
      </div>
    `).join("");
  } catch(e) { container.innerHTML = `<p class="muted" style="color:var(--red)">Error: ${e.message}</p>`; }
}

$("btn-action").addEventListener("click", async () => {
  const fileId     = $("tl-file-id").value.trim();
  const actorId    = $("tl-actor").value;
  const actionType = $("tl-action-type").value;
  const declared   = $("tl-transform").value.trim();
  const file       = $("tl-file").files[0];

  if (!fileId || !actorId) { showResult("action-result", "File ID and custodian are required.", true); return; }
  if (actionType === "MODIFY" && !file) { showResult("action-result", "MODIFY requires a file upload.", true); return; }

  const fd = new FormData();
  fd.append("actor_id", actorId);
  fd.append("action_type", actionType);
  if (declared) fd.append("declared_transformation", declared);
  if (file) fd.append("file", file);

  try {
    const r = await fetch(`${API}/files/${fileId}/action`, { method: "POST", body: fd });
    const data = await r.json();
    if (data.error) { showResult("action-result", data.error, true); return; }
    showResult("action-result", { "New Record Hash": data.record_hash });
    loadHistory(fileId);
  } catch(e) { showResult("action-result", `Error: ${e.message}`, true); }
});

// ── Screen 4: Verify ───────────────────────────────────────────
$("btn-verify").addEventListener("click", async () => {
  const fileId = $("verify-file-id").value.trim();
  const file   = $("verify-file").files[0];
  if (!fileId || !file) { return; }

  const fd = new FormData();
  fd.append("file", file);

  try {
    const res = await fetch(`${API}/files/${fileId}/verify`, { method: "POST", body: fd });
    const result = await res.json();
    renderVerdict(result);

    // If image, also fetch ELA
    if (file.type.startsWith("image/")) {
      fetchELA(fileId, file);
    } else {
      $("ela-wrap").classList.add("hidden");
    }
  } catch(e) {
    $("verdict-wrap").classList.remove("hidden");
    $("verdict-badge").textContent = `⚠️ Network error: ${e.message}`;
    $("verdict-badge").className = "badge badge-unknown";
  }
});

function renderVerdict(result) {
  const wrap  = $("verdict-wrap");
  const badge = $("verdict-badge");
  const detail = $("verdict-detail");

  wrap.classList.remove("hidden");
  badge.className = "badge"; // reset

  if (result.status === "VERIFIED") {
    badge.textContent = `✅ VERIFIED — ${result.hops} custody hop${result.hops>1?'s':''} confirmed`;
    badge.classList.add("badge-verified");
    detail.textContent = "The file's full chain of custody is cryptographically intact. Every signature is valid, every hash matches.";
  } else if (result.status === "TAMPERED") {
    badge.textContent = `🚨 TAMPERED — broke at hop ${result.broken_at}`;
    badge.classList.add("badge-tampered");
    detail.textContent = `Reason: ${result.reason}`;
  } else {
    badge.textContent = `⚠️ UNKNOWN PROVENANCE`;
    badge.classList.add("badge-unknown");
    detail.textContent = result.reason || "No custody history found for this file ID.";
  }
}

async function fetchELA(fileId, file) {
  const fd = new FormData();
  fd.append("file", file);
  try {
    const r = await fetch(`${API}/files/${fileId}/ela`, { method: "POST", body: fd });
    if (r.ok) {
      const blob = await r.blob();
      $("ela-img").src = URL.createObjectURL(blob);
      $("ela-wrap").classList.remove("hidden");
    }
  } catch {}
}

// ── Init ───────────────────────────────────────────────────────
// Pre-load users on register screen on boot
window.addEventListener("load", () => {
  loadUsers();
});
