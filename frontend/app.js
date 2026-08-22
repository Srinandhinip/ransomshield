// RansomShield frontend
// Same-origin API - the FastAPI backend serves this file itself, so
// no base URL / CORS configuration is needed.
const API_URL = "";

let riskHistory = [];

// --------------------------------------------------
// NAVIGATION
// --------------------------------------------------

const navLinks = document.querySelectorAll(".nav-link");
const pages = document.querySelectorAll(".page");

navLinks.forEach(link => {
    link.addEventListener("click", () => {
        const target = link.dataset.page;

        navLinks.forEach(l => l.classList.remove("active"));
        link.classList.add("active");

        pages.forEach(p => p.classList.remove("active"));
        document.getElementById(`page-${target}`).classList.add("active");
    });
});

// --------------------------------------------------
// HELPERS
// --------------------------------------------------

function timeAgo(isoString) {
    if (!isoString) return "--";
    const diff = (Date.now() - new Date(isoString).getTime()) / 1000;
    if (diff < 5) return "just now";
    if (diff < 60) return `${Math.floor(diff)}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    return `${Math.floor(diff / 3600)}h ago`;
}

function statusColorClass(status) {
    switch (status) {
        case "CRITICAL": return "status-critical";
        case "HIGH": return "status-high";
        case "SUSPICIOUS": return "status-suspicious";
        default: return "status-normal";
    }
}

function eventIcon(type) {
    switch (type) {
        case "created": return "add_circle";
        case "modified": return "edit";
        case "deleted": return "delete";
        case "renamed": return "drive_file_rename_outline";
        default: return "info";
    }
}

function showToast(message) {
    const toast = document.getElementById("toast");
    toast.textContent = message;
    toast.style.opacity = "1";
    toast.style.transform = "translateY(0)";
    clearTimeout(showToast._t);
    showToast._t = setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transform = "translateY(8px)";
    }, 3000);
}

async function api(path, options) {
    const response = await fetch(`${API_URL}${path}`, options);
    if (!response.ok) {
        throw new Error(`${path} -> ${response.status}`);
    }
    return response.json();
}

// --------------------------------------------------
// CONNECTION INDICATOR
// --------------------------------------------------

function setConnected(ok) {
    const dot = document.getElementById("connDot");
    const label = document.getElementById("connLabel");
    if (ok) {
        dot.className = "w-2 h-2 rounded-full bg-primary-fixed-dim pulse-glow";
        label.textContent = "LIVE - Connected to RansomShield backend";
    } else {
        dot.className = "w-2 h-2 rounded-full bg-error";
        label.textContent = "Backend unreachable - retrying...";
    }
}

// --------------------------------------------------
// DASHBOARD
// --------------------------------------------------

function renderDashboard(state) {
    const score = state.risk_score;
    const status = state.status;

    document.getElementById("riskScore").textContent = score;
    document.getElementById("riskScore").className =
        `font-display-lg text-display-lg ${statusColorClass(status)}`;
    document.getElementById("riskLabel").textContent =
        status === "NORMAL" ? "LOW RISK" : status;
    document.getElementById("riskLabel").className =
        `font-data-mono text-data-mono text-[10px] ${statusColorClass(status)}`;

    document.getElementById("filesMonitored").textContent = state.files_monitored;
    document.getElementById("threatsBlocked").textContent = state.threats_blocked;
    document.getElementById("statusText").textContent = status;
    document.getElementById("statusText").className =
        `font-headline-md text-headline-md ${statusColorClass(status)}`;

    // Gauge
    const circumference = 251.2;
    const offset = circumference - (circumference * score) / 100;
    const ring = document.getElementById("gaugeCircle");
    ring.setAttribute("stroke-dashoffset", offset.toFixed(1));
    ring.setAttribute(
        "class",
        status === "CRITICAL" || status === "HIGH" ? "text-error" :
        status === "SUSPICIOUS" ? "text-yellow-400" : "text-green-400"
    );
    document.getElementById("gaugeScore").textContent = score;
    document.getElementById("gaugeScore").className =
        `font-display-lg text-display-lg leading-none ${statusColorClass(status)}`;

    const banner = document.getElementById("assessmentBanner");
    const bannerText = document.getElementById("assessmentText");
    const bannerIcon = document.getElementById("assessmentIcon");
    if (status === "NORMAL") {
        banner.className = "px-6 py-3 rounded flex items-center gap-3 bg-green-400/10 border border-green-400/30";
        bannerIcon.className = "material-symbols-outlined text-green-400";
        bannerIcon.textContent = "check_circle";
        bannerText.textContent = "System Secure. No ransomware behavior detected.";
    } else {
        banner.className = "px-6 py-3 rounded flex items-center gap-3 bg-error-container/20 border border-error/40";
        bannerIcon.className = "material-symbols-outlined text-error";
        bannerIcon.textContent = "warning";
        bannerText.textContent = state.honeypot_triggered
            ? "Honeypot triggered - possible ransomware activity!"
            : `Elevated risk detected (${status}). Review Threat Monitor for details.`;
    }

    // Telemetry list
    const activityBox = document.getElementById("dashboardActivity");
    if (!state.activity || state.activity.length === 0) {
        activityBox.innerHTML = `<div class="text-outline-variant text-xs p-3">No filesystem activity yet.</div>`;
    } else {
        activityBox.innerHTML = state.activity.slice(0, 8).map(item => `
            <div class="grid grid-cols-12 gap-2 px-2 py-1.5 hover:bg-surface-container-high rounded transition-colors">
                <div class="col-span-3 text-outline-variant">${timeAgo(item.time)}</div>
                <div class="col-span-3 text-on-surface uppercase">${item.type}</div>
                <div class="col-span-6 text-on-surface-variant truncate" title="${item.file}">${item.file.split(/[\\/]/).pop()}</div>
            </div>
        `).join("");
    }

    // Trend chart
    riskHistory.push(score);
    if (riskHistory.length > 20) riskHistory.shift();
    renderTrendChart();
}

function renderTrendChart() {
    const svg = document.getElementById("trendChart");
    const emptyMsg = document.getElementById("trendEmpty");

    if (riskHistory.length < 2) {
        svg.innerHTML = "";
        emptyMsg.style.display = "block";
        return;
    }
    emptyMsg.style.display = "none";

    const step = 1000 / (riskHistory.length - 1);
    const points = riskHistory.map((v, i) => `${(i * step).toFixed(1)},${(100 - v).toFixed(1)}`).join(" ");

    svg.innerHTML = `
        <polyline fill="none" points="${points}" stroke="#00daf3" stroke-width="2" vector-effect="non-scaling-stroke"/>
        ${riskHistory.map((v, i) => `<circle cx="${(i * step).toFixed(1)}" cy="${(100 - v).toFixed(1)}" r="2.5" fill="#00daf3"/>`).join("")}
    `;
}

// --------------------------------------------------
// THREAT MONITOR
// --------------------------------------------------

function renderThreatMonitor(state, events) {
    const feed = document.getElementById("threatFeed");
    if (!events || events.length === 0) {
        feed.innerHTML = `<div class="text-outline-variant">Waiting for filesystem activity...</div>`;
    } else {
        feed.innerHTML = events.slice(0, 25).map(e => {
            const isHoneypot = e.honeypot_triggered;
            const isHigh = e.severity === "HIGH" || e.severity === "CRITICAL";
            const rowClass = isHoneypot
                ? "flex gap-4 items-center py-3 px-3 my-1 border border-error bg-error-container/20 rounded pulse-critical"
                : isHigh
                    ? "flex gap-4 items-start py-1.5 border-b border-outline-variant/30 bg-error-container/10"
                    : "flex gap-4 items-start py-1.5 border-b border-outline-variant/30 hover:bg-surface-container-low transition-colors";
            return `
                <div class="${rowClass}">
                    <span class="${isHoneypot || isHigh ? 'text-error' : 'text-on-surface-variant opacity-70'} w-24 shrink-0">${new Date(e.timestamp).toLocaleTimeString()}</span>
                    <span class="${isHoneypot || isHigh ? 'text-error font-bold' : 'text-primary'} w-20 shrink-0">${e.event_type.toUpperCase()}</span>
                    <span class="${isHoneypot ? 'text-error font-bold' : 'text-on-surface truncate'} flex-1 truncate" title="${e.file_path || ''}">
                        ${isHoneypot ? "🍯 HONEYPOT TRIGGERED - " : ""}${(e.file_path || "").split(/[\\/]/).pop() || e.message}
                    </span>
                </div>
            `;
        }).join("");
    }

    const ind = state.indicators || {};
    const items = [
        { label: "File Modification", value: Math.min(ind.modified_files * 10, 100), raw: ind.modified_files },
        { label: "File Renaming", value: Math.min(ind.renamed_files * 10, 100), raw: ind.renamed_files },
        { label: "Deletion Activity", value: Math.min(ind.deleted_files * 10, 100), raw: ind.deleted_files },
        { label: "Suspicious Extensions", value: Math.min((ind.suspicious_extensions || []).length * 20, 100), raw: (ind.suspicious_extensions || []).length },
        { label: "Honeypot Interaction", value: state.honeypot_triggered ? 100 : 0, raw: state.honeypot_triggered ? "YES" : "NO" },
    ];

    document.getElementById("behaviorIndicators").innerHTML = items.map(item => {
        const critical = item.value >= 70;
        return `
        <div>
            <div class="flex justify-between mb-1.5 font-data-mono text-data-mono text-[12px]">
                <span class="${critical ? 'text-error' : 'text-on-surface'}">${item.label}</span>
                <span class="${critical ? 'text-error font-bold' : 'text-primary-fixed-dim'}">${item.raw}</span>
            </div>
            <div class="w-full bg-surface-container-lowest h-1.5 rounded-full overflow-hidden border border-outline-variant/50">
                <div class="${critical ? 'bg-error' : 'bg-primary-fixed-dim'} h-full" style="width:${item.value}%"></div>
            </div>
        </div>`;
    }).join("");

    const gaugeCard = document.getElementById("threatGaugeCard");
    const gaugeScore = document.getElementById("threatGaugeScore");
    const gaugeStatus = document.getElementById("threatGaugeStatus");
    gaugeScore.innerHTML = `${state.risk_score}<span class="text-[24px] opacity-70 font-normal">/100</span>`;
    gaugeStatus.textContent = state.status;

    if (state.status === "CRITICAL" || state.status === "HIGH") {
        gaugeCard.className = "bg-error-container/10 border border-error/50 rounded p-6 flex flex-col items-center justify-center h-40 pulse-critical";
        gaugeScore.className = "font-display-lg text-display-lg font-bold tracking-tighter flex items-baseline text-error";
        gaugeStatus.className = "font-label-caps text-label-caps px-4 py-1 mt-3 rounded-full tracking-widest bg-error text-on-error";
    } else {
        gaugeCard.className = "bg-green-400/5 border border-green-400/30 rounded p-6 flex flex-col items-center justify-center h-40";
        gaugeScore.className = "font-display-lg text-display-lg font-bold tracking-tighter flex items-baseline text-green-400";
        gaugeStatus.className = "font-label-caps text-label-caps px-4 py-1 mt-3 rounded-full tracking-widest bg-green-400/20 text-green-400";
    }
}

// --------------------------------------------------
// SECURITY EVENTS
// --------------------------------------------------

function renderEvents(events) {
    const table = document.getElementById("eventsTable");
    if (!events || events.length === 0) {
        table.innerHTML = `<div class="p-6 text-outline-variant text-sm">No events logged yet.</div>`;
        return;
    }
    table.innerHTML = events.map(e => `
        <div class="grid grid-cols-12 gap-2 px-4 py-2.5 hover:bg-surface-container-high transition-colors">
            <div class="col-span-2 text-outline-variant">${new Date(e.timestamp).toLocaleTimeString()}</div>
            <div class="col-span-2 text-on-surface flex items-center gap-1">
                <span class="material-symbols-outlined text-[14px]">${eventIcon(e.event_type)}</span>${e.event_type}
            </div>
            <div class="col-span-5 text-on-surface-variant truncate" title="${e.file_path || ''}">${e.file_path || e.message || "--"}</div>
            <div class="col-span-2 ${statusColorClass(e.severity)}">${e.severity}${e.honeypot_triggered ? " 🍯" : ""}</div>
            <div class="col-span-1">${e.risk_score}</div>
        </div>
    `).join("");
}

// --------------------------------------------------
// RISK ANALYSIS
// --------------------------------------------------

function renderRiskAnalysis(state) {
    document.getElementById("riskAnalysisScore").textContent = state.risk_score;
    document.getElementById("riskAnalysisScore").className =
        `font-display-lg text-display-lg ${statusColorClass(state.status)}`;

    const ind = state.indicators || {};
    let rationale = "No suspicious behavior detected in the last 10-second window.";
    if (state.honeypot_triggered) {
        rationale = "A honeypot file was accessed - this is a strong indicator of active ransomware behavior.";
    } else if (state.status !== "NORMAL") {
        rationale = `Elevated activity: ${ind.modified_files || 0} files modified, ${ind.renamed_files || 0} renamed, ${ind.deleted_files || 0} deleted within a 10-second window.`;
    }
    document.getElementById("riskRationale").textContent = rationale;

    const contributors = [
        { label: "Modified files (10s window)", value: ind.modified_files || 0, max: 50 },
        { label: "Renamed files (10s window)", value: ind.renamed_files || 0, max: 20 },
        { label: "Deleted files (10s window)", value: ind.deleted_files || 0, max: 20 },
        { label: "Unique files touched", value: ind.unique_files || 0, max: 50 },
    ];
    document.getElementById("riskContributors").innerHTML = contributors.map(c => {
        const pct = Math.min((c.value / c.max) * 100, 100);
        return `
        <div>
            <div class="flex justify-between text-sm mb-1">
                <span class="text-on-surface-variant">${c.label}</span>
                <span class="text-on-surface font-data-mono">${c.value}</span>
            </div>
            <div class="w-full bg-surface-container-lowest h-2 rounded-full overflow-hidden border border-outline-variant/50">
                <div class="bg-primary-fixed-dim h-full" style="width:${pct}%"></div>
            </div>
        </div>`;
    }).join("");

    const extBox = document.getElementById("suspiciousExtensions");
    const exts = ind.suspicious_extensions || [];
    extBox.innerHTML = exts.length === 0
        ? `<span class="text-on-surface-variant text-sm">None detected</span>`
        : exts.map(f => `<span class="bg-error-container/20 border border-error/40 text-error px-3 py-1 rounded text-xs font-data-mono">${f.split(/[\\/]/).pop()}</span>`).join("");
}

// --------------------------------------------------
// DECEPTION CENTER
// --------------------------------------------------

function renderHoneypots(data) {
    const grid = document.getElementById("honeypotGrid");
    grid.innerHTML = data.honeypots.map(h => `
        <div class="bg-surface-container/40 border ${data.triggered ? 'border-error/50' : 'border-outline-variant'} rounded p-5 flex flex-col gap-3">
            <div class="flex items-center justify-between">
                <span class="material-symbols-outlined ${h.exists ? 'text-primary-fixed-dim' : 'text-outline'}">bug_report</span>
                <span class="font-label-caps text-label-caps ${h.exists ? 'text-green-400' : 'text-outline'}">${h.exists ? "DEPLOYED" : "MISSING"}</span>
            </div>
            <span class="font-data-mono text-data-mono text-sm truncate">${h.filename}</span>
            <span class="text-outline-variant text-[10px] truncate">${h.path}</span>
        </div>
    `).join("");
}

// --------------------------------------------------
// INCIDENTS
// --------------------------------------------------

function renderIncidents(incidents) {
    const list = document.getElementById("incidentsList");
    if (!incidents || incidents.length === 0) {
        list.innerHTML = `<div class="text-outline-variant text-sm p-4">No incidents recorded. System has been operating normally.</div>`;
        return;
    }
    list.innerHTML = incidents.map(inc => `
        <div class="bg-surface-container/40 border border-outline-variant rounded p-4 flex items-center justify-between">
            <div>
                <div class="flex items-center gap-2 mb-1">
                    <span class="font-data-mono text-data-mono text-sm">${inc.incident_id}</span>
                    <span class="${statusColorClass(inc.severity)} font-label-caps text-label-caps px-2 py-0.5 rounded bg-surface-container-high">${inc.severity}</span>
                    <span class="text-outline-variant text-xs">${new Date(inc.created_at).toLocaleString()}</span>
                </div>
                <p class="text-on-surface-variant text-sm">${inc.reason}</p>
            </div>
            <div class="flex items-center gap-3">
                <span class="text-on-surface font-data-mono">${inc.risk_score}/100</span>
                <select data-id="${inc.incident_id}" class="incident-status bg-surface-container-high border border-outline-variant rounded px-2 py-1 text-xs">
                    ${["OPEN", "INVESTIGATING", "CONTAINED", "RECOVERED", "CLOSED"].map(s =>
                        `<option value="${s}" ${s === inc.status ? "selected" : ""}>${s}</option>`).join("")}
                </select>
            </div>
        </div>
    `).join("");

    document.querySelectorAll(".incident-status").forEach(select => {
        select.addEventListener("change", async (e) => {
            const id = e.target.dataset.id;
            try {
                await api(`/incidents/${id}/status`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ status: e.target.value })
                });
                showToast(`${id} updated to ${e.target.value}`);
            } catch (err) {
                showToast("Failed to update incident status");
            }
        });
    });
}

// --------------------------------------------------
// MAIN POLL LOOP
// --------------------------------------------------

async function refreshAll() {
    try {
        const [state, eventsData, incidentsData, honeypotsData] = await Promise.all([
            api("/status"),
            api("/events?limit=50"),
            api("/incidents?limit=50"),
            api("/honeypots"),
        ]);

        setConnected(true);

        renderDashboard(state);
        renderThreatMonitor(state, eventsData.events);
        renderEvents(eventsData.events);
        renderRiskAnalysis(state);
        renderHoneypots(honeypotsData);
        renderIncidents(incidentsData.incidents);

        document.getElementById("honeypotCount").textContent =
            honeypotsData.honeypots.filter(h => h.exists).length;

    } catch (error) {
        console.error("RansomShield API error:", error);
        setConnected(false);
    }
}

// --------------------------------------------------
// ACTIONS
// --------------------------------------------------

document.getElementById("simulateBtn").addEventListener("click", async () => {
    const btn = document.getElementById("simulateBtn");
    btn.disabled = true;
    btn.classList.add("opacity-60");
    try {
        await api("/simulate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ trigger_honeypot: false })
        });
        showToast("Simulation started - watch the dashboard update");
    } catch (err) {
        showToast("Failed to start simulation");
    } finally {
        setTimeout(() => {
            btn.disabled = false;
            btn.classList.remove("opacity-60");
        }, 2000);
    }
});

document.getElementById("resetBtn").addEventListener("click", async () => {
    try {
        await api("/reset", { method: "POST" });
        riskHistory = [];
        showToast("Demo state reset");
        refreshAll();
    } catch (err) {
        showToast("Failed to reset state");
    }
});

// --------------------------------------------------
// START
// --------------------------------------------------

refreshAll();
setInterval(refreshAll, 2000);
