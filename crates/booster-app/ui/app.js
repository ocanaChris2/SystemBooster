// SystemBooster front-end controller.
//
// Talks to the Tauri backend via `invoke()` when running inside the desktop
// app. When opened in a plain browser (design preview / `npx serve`), it falls
// back to in-page mock data so the UI is fully navigable without the service.

const tauri = window.__TAURI__?.core;
const IN_APP = !!tauri;

async function invoke(cmd, args) {
  if (IN_APP) return tauri.invoke(cmd, args);
  return mockInvoke(cmd, args);
}

const state = {
  profile: "Gaming",
  boosted: false,
  memTotal: 16 * 1024 ** 3,
};

const $ = (sel) => document.querySelector(sel);
const app = $(".app");

// ---- Navigation ----
document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    const view = btn.dataset.view;
    document.querySelectorAll(".view").forEach((v) => v.classList.add("hidden"));
    $(`#view-${view}`).classList.remove("hidden");
    if (view === "apps") loadCandidates();
  });
});

document.querySelectorAll(".profile").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".profile").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    state.profile = btn.dataset.profile;
    $("#active-profile").textContent = state.profile;
  });
});

// ---- Boost toggle ----
$("#boost-btn").addEventListener("click", async () => {
  if (!state.boosted) {
    const res = await invoke("start_boost", { profile: state.profile });
    const report = res.Boosted;
    if (report) {
      state.boosted = true;
      app.classList.add("boosted");
      $("#boost-label").textContent = "RESTORE";
      $("#boost-counts").textContent =
        `Suspended ${report.suspended_processes} processes · ${report.changed_services} services`;
      $("#freed-value").textContent = "+1.8 GB";
      startHeartbeat();
      addLog(`Boost started (${state.profile})`);
    } else if (res.Error) {
      $("#boost-counts").textContent = "Error: " + res.Error.message;
    }
  } else {
    await invoke("end_boost");
    state.boosted = false;
    app.classList.remove("boosted");
    $("#boost-label").textContent = "BOOST NOW";
    $("#boost-counts").textContent = "Restored — system back to normal.";
    $("#freed-value").textContent = "+0 GB";
    stopHeartbeat();
    addLog("Boost ended — all items restored");
  }
  refreshStatus();
});

// ---- Heartbeat: keeps the service watchdog from auto-restoring ----
let hbTimer = null;
function startHeartbeat() {
  stopHeartbeat();
  hbTimer = setInterval(() => invoke("heartbeat"), 5000);
}
function stopHeartbeat() {
  if (hbTimer) clearInterval(hbTimer);
  hbTimer = null;
}

// ---- Status / metrics ----
async function refreshStatus() {
  try {
    const res = await invoke("get_status");
    const st = res.Status;
    if (!st) return;
    $("#svc-dot").className = "dot ok";
    $("#svc-status").textContent = "Service: OK";
    const m = st.metrics;
    const pct = m.memory_load_percent;
    state.memTotal = m.total_physical_bytes || state.memTotal;
    const usedGb = ((m.total_physical_bytes - m.available_physical_bytes) / 1024 ** 3).toFixed(1);
    $("#mem-value").textContent = `${pct}% (${usedGb} GB)`;
    $("#mem-bar").style.width = pct + "%";
  } catch (e) {
    $("#svc-dot").className = "dot bad";
    $("#svc-status").textContent = "Service: unavailable";
  }
}

// ---- Apps & Services list ----
async function loadCandidates() {
  const res = await invoke("scan", { profile: state.profile });
  const scan = res.Scan;
  if (!scan) return;
  $("#proc-list").innerHTML = scan.processes.map(renderCandidate).join("");
  $("#svc-list").innerHTML = scan.services.map(renderCandidate).join("");
}

function renderCandidate(c) {
  const cls = c.eligible ? "candidate" : "candidate locked";
  const tag = c.eligible
    ? '<span class="tag eligible">eligible</span>'
    : '<span class="tag locked">protected</span>';
  return `<li class="${cls}"><span>${escapeHtml(c.name)}</span>${tag}</li>`;
}

// ---- Logs ----
function addLog(msg) {
  const li = document.createElement("li");
  li.className = "log";
  li.innerHTML = `<div>${escapeHtml(msg)}</div><div class="when">${new Date().toLocaleTimeString()}</div>`;
  $("#log-list").prepend(li);
}

function escapeHtml(s) {
  return s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}

// ---- Browser-preview mock backend ----
function mockInvoke(cmd, args) {
  switch (cmd) {
    case "scan":
      return Promise.resolve({
        Scan: {
          processes: [
            { key: "1500", name: "Spotify.exe", eligible: true },
            { key: "1600", name: "Slack.exe", eligible: true },
            { key: "800", name: "lsass.exe", eligible: false },
            { key: "900", name: "csrss.exe", eligible: false },
          ],
          services: [
            { key: "WSearch", name: "Windows Search", eligible: true },
            { key: "Spooler", name: "Print Spooler", eligible: true },
            { key: "RpcSs", name: "Remote Procedure Call", eligible: false },
          ],
        },
      });
    case "start_boost":
      return Promise.resolve({
        Boosted: { session_id: "0", suspended_processes: 23, changed_services: 11, skipped: [] },
      });
    case "end_boost":
      return Promise.resolve({ Ended: null });
    case "heartbeat":
      return Promise.resolve({ Ack: null });
    case "get_status":
      return Promise.resolve({
        Status: {
          boosted: state.boosted,
          active_profile: state.profile,
          metrics: {
            memory_load_percent: state.boosted ? 44 : 62,
            total_physical_bytes: 16 * 1024 ** 3,
            available_physical_bytes: (state.boosted ? 9 : 6) * 1024 ** 3,
          },
        },
      });
    default:
      return Promise.resolve({});
  }
}

// ---- Init ----
$("#active-profile").textContent = state.profile;
refreshStatus();
setInterval(refreshStatus, 4000);
if (!IN_APP) addLog("Preview mode — service not connected (mock data)");
