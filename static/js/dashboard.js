const state = {
    summary: null,
    trend: [],
    cves: [],
    ransomware: [],
    attacks: [],
    events: [],
    industries: [],
    feedStatus: [],
    aiSummary: null,
    alerts: [],
    assets: [],
    incidents: [],
    opsHealth: null,
    liveFeeds: null,
    markerElements: [],
    liveThreats: [],
    startedAt: Date.now(),
    rotation: 0,
    activeIncidentId: null,
    telemetryHistory: [],
    sensorHistory: [],
};

const clocks = [
    ["NYC", "America/New_York"],
    ["LA", "America/Los_Angeles"],
    ["LON", "Europe/London"],
    ["MOS", "Europe/Moscow"],
    ["DXB", "Asia/Dubai"],
    ["BOM", "Asia/Kolkata"],
    ["HKG", "Asia/Hong_Kong"],
];

const liveEvents = [];

const countryOutlines = [
    [[71,-168],[69,-140],[61,-124],[49,-123],[32,-117],[19,-99],[8,-82],[15,-61],[31,-80],[45,-70],[56,-77],[70,-95],[71,-168]],
    [[12,-82],[5,-78],[-12,-77],[-35,-71],[-55,-67],[-52,-45],[-23,-43],[-5,-35],[6,-50],[12,-82]],
    [[36,-10],[44,-9],[52,0],[58,10],[69,30],[60,60],[50,45],[42,30],[36,15],[36,-10]],
    [[35,-17],[31,10],[12,18],[2,30],[-18,24],[-35,18],[-35,32],[-22,45],[6,50],[25,35],[35,20],[35,-17]],
    [[72,35],[62,80],[55,120],[42,135],[30,122],[20,104],[8,78],[22,58],[40,45],[55,60],[72,35]],
    [[35,68],[31,77],[21,88],[8,80],[18,72],[25,68],[35,68]],
    [[45,126],[39,140],[32,132],[36,122],[45,126]],
    [[45,142],[36,145],[31,131],[42,129],[45,142]],
    [[-10,112],[-20,114],[-35,125],[-43,147],[-31,153],[-17,145],[-10,112]],
    [[-35,166],[-43,172],[-46,168],[-40,162],[-35,166]],
    [[82,-52],[75,-45],[70,-30],[63,-42],[68,-58],[82,-52]],
];

const countryLabels = [
    { code: "US", lat: 39, lng: -98 },
    { code: "BR", lat: -10, lng: -52 },
    { code: "UK", lat: 55, lng: -3 },
    { code: "DE", lat: 51, lng: 10 },
    { code: "RU", lat: 61, lng: 90 },
    { code: "IN", lat: 22, lng: 79 },
    { code: "CN", lat: 35, lng: 103 },
    { code: "JP", lat: 37, lng: 138 },
    { code: "AU", lat: -25, lng: 134 },
    { code: "ZA", lat: -30, lng: 24 },
];

function text(id, value) {
    const element = document.getElementById(id);
    if (element) element.textContent = value;
}

async function getJson(url) {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`${url} returned ${response.status}`);
    return response.json();
}

async function safeJson(url, fallback) {
    try {
        return await getJson(url);
    } catch (error) {
        console.warn(`Feed unavailable: ${url}`);
        return fallback;
    }
}

function mutationHeaders() {
    return { "Content-Type": "application/json", "X-CSRF-Token": document.querySelector('meta[name="csrf-token"]')?.content || "" };
}

function emptyState(message) {
    return `<div class="empty-state"><span class="empty-state-dot"></span>${message}</div>`;
}

function renderClocks() {
    const container = document.getElementById("world-clocks");
    if (!container) return;

    container.innerHTML = clocks.map(([label, zone]) => {
        const time = new Intl.DateTimeFormat("en-US", {
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
            hour12: false,
            timeZone: zone,
        }).format(new Date());
        return `<div><span>${label}</span>${time}</div>`;
    }).join("");
}

function renderLiveFeedTables() {
    const bgp = document.getElementById("bgp-feed");
    const outages = document.getElementById("outage-feed");
    const bgpRows = state.liveFeeds?.bgp?.items || [];
    const outageRows = state.liveFeeds?.outages?.items || [];
    renderPanelStatuses();

    if (bgp) {
        bgp.innerHTML = bgpRows.length ? bgpRows.map(row => `
            <div class="table-row">
                <span class="badge">${row.cc || "--"}</span>
                <span class="row-title">${row.isp || row.asn || "Unknown"}</span>
                <span class="row-meta">${row.prefix || row.ago || "--"}</span>
            </div>
        `).join("") : emptyState("RADAR DATA WAITING");
    }

    if (outages) {
        outages.innerHTML = outageRows.length ? outageRows.map(row => `
            <div class="table-row">
                <span class="badge">${row.cc || "--"}</span>
                <span class="row-title">${row.cause || "anomaly"}</span>
                <span class="${row.state === "active" ? "row-hot" : "row-meta"}">${row.state || "live"}</span>
            </div>
        `).join("") : emptyState("NO OUTAGE OBSERVATION");
    }
}

function renderSummary() {
    const summary = state.summary;
    if (!summary) return;

    text("critical-cves", summary.criticalCves);
    text("active-exploits", summary.activeExploits);
    text("threat-actors", summary.threatActors);
    text("victims", summary.victims);
    text("threat-score", liveThreatScore(summary.threatScore).toFixed(1));
    text("assessment-state", summary.assessment);
    text("assessment-score", `${liveThreatScore(summary.threatScore).toFixed(1)} / 10`);
    if (!state.aiSummary) {
        text("assessment-copy", `${summary.activeExploits} exploited vulnerabilities, ${summary.victims} ransomware victims, and ${summary.activeAttacks} global intelligence markers are in view. This is not proof of local compromise.`);
    }
    const liveFeeds = state.feedStatus.filter(feed => displayState(feed) === "LIVE").length;
    text("feed-count", `${liveFeeds}/${state.feedStatus.length || 0} FEEDS LIVE`);
}

function liveThreatScore(baseScore) {
    const wave = Math.sin(Date.now() / 7000) * 0.2;
    return Math.max(0, Math.min(10, baseScore + wave));
}

function severityClass(value) {
    const severity = String(value || "").toLowerCase();
    if (severity.includes("critical") || severity.includes("ransom")) return "red";
    if (severity.includes("high") || severity.includes("outage")) return "amber";
    if (severity.includes("hijack")) return "violet";
    if (severity.includes("scan")) return "blue";
    return "green";
}

function renderCves() {
    const container = document.getElementById("cve-feed");
    if (!container) return;

    container.innerHTML = state.cves.length ? state.cves.map((cve, index) => `
        <div class="table-row clickable" data-incident-type="cve" data-incident-index="${index}">
            <span class="row-title">${cve.id}</span>
            <span>${cve.vendor} - ${cve.product}</span>
            <span class="${severityClass(cve.severity)}">${Number(cve.cvss || 0).toFixed(1)}</span>
        </div>
    `).join("") : emptyState("CVE FEED WAITING");
}

function renderRansomware() {
    const container = document.getElementById("ransomware-feed");
    if (!container) return;

    container.innerHTML = state.ransomware.length ? state.ransomware.map((item, index) => `
        <div class="table-row clickable" data-incident-type="ransomware" data-incident-index="${index}">
            <span class="row-title">${item.victim}</span>
            <span class="red">${item.group}</span>
            <span class="badge">${item.country.slice(0, 2).toUpperCase()}</span>
        </div>
    `).join("") : emptyState("NO VICTIM DATA");
}

function renderEvents() {
    const container = document.getElementById("event-log");
    if (!container) return;

    const combinedEvents = [
        ...liveEvents,
        ...state.events.map(event => ({
            title: event.title,
            createdAt: event.createdAt,
            severity: event.severity,
        })),
    ].slice(0, 24);

    container.innerHTML = combinedEvents.length ? combinedEvents.map((event, index) => {
        const date = new Date(event.createdAt);
        const time = Number.isNaN(date.getTime()) ? "--:--" : date.toLocaleTimeString([], { hour12: false });
        return `
            <div class="event-item clickable" data-incident-type="event" data-incident-index="${index}">
                <time>${time}</time>
                <span>${event.title}</span>
            </div>
        `;
    }).join("") : emptyState("EVENT STREAM WAITING");
    state.combinedEvents = combinedEvents;
}

function logLiveEvent(type, message) {
    liveEvents.unshift({
        title: message,
        createdAt: new Date().toISOString(),
        severity: type,
    });
    if (liveEvents.length > 30) liveEvents.pop();
    renderEvents();
}

async function loadEventsOnly() {
    state.events = await getJson("/api/events");
    liveEvents.length = 0;
    renderEvents();
}

function startEventStream() {
    if (!window.EventSource) {
        setInterval(() => loadEventsOnly().catch(console.error), 5000);
        return;
    }

    const stream = new EventSource("/api/events/stream");
    stream.addEventListener("events", event => {
        try {
            state.events = JSON.parse(event.data);
            liveEvents.length = 0;
            renderEvents();
        } catch (error) {
            console.error("Event stream parse failed", error);
        }
    });
    stream.onerror = () => {
        logLiveEvent("feed", "Live event stream reconnecting");
        setTimeout(() => loadEventsOnly().catch(console.error), 1000);
    };
}

function renderIndustries() {
    const container = document.getElementById("industry-list");
    if (!container) return;
    const max = Math.max(...state.industries.map(item => item.count), 1);

    container.innerHTML = state.industries.length ? state.industries.map(item => `
        <div class="industry-item">
            <span>${item.name}</span>
            <strong>${item.count}</strong>
            <div class="bar"><span style="width:${(item.count / max) * 100}%"></span></div>
        </div>
    `).join("") : emptyState("INDUSTRY DATA WAITING");
}

function formatRelativeTime(value) {
    if (!value) return "not synced";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "unknown";
    const seconds = Math.max(0, Math.floor((Date.now() - date.getTime()) / 1000));
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
}

function formatTimestamp(value) {
    if (!value) return "never";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "unknown";
    return `${date.toISOString().replace("T", " ").replace(".000Z", " UTC")}`;
}

function displayState(feed) {
    if (feed?.state) return feed.state;
    if (feed?.status === "online") return "LIVE";
    if (feed?.status === "fallback") return "FALLBACK";
    return "OFFLINE";
}

function stateClass(feed) {
    return displayState(feed).toLowerCase();
}

function feedByName(name) {
    return state.feedStatus.find(feed => feed.name === name);
}

function freshnessText(feed) {
    const state = displayState(feed);
    const checked = `checked ${formatRelativeTime(feed.checkedAt)}`;
    if (state === "LIVE") {
        return `updated ${formatRelativeTime(feed.updatedAt || feed.lastSync)} · ${checked} · ${formatTimestamp(feed.updatedAt || feed.lastSync)}`;
    }
    if (state === "FALLBACK") return `fallback data · ${checked}`;
    return `no live data · ${checked}`;
}

function renderPanelStatuses() {
    const mappings = [
        ["bgp-panel-status", "Cloudflare Radar"],
        ["outage-panel-status", "Cloudflare Radar"],
        ["solar-panel-status", "NOAA SWPC"],
        ["backend-panel-status", "Cyberwatch Monitor"],
        ["cve-panel-status", "CISA KEV"],
        ["ransomware-panel-status", "Ransomware"],
        ["event-panel-status", "Cyberwatch Monitor"],
    ];
    mappings.forEach(([id, name]) => {
        const element = document.getElementById(id);
        const feed = feedByName(name);
        if (!element || !feed) return;
        element.textContent = displayState(feed);
        element.className = `panel-state ${stateClass(feed)}`;
        element.title = freshnessText(feed);
    });
}

function renderFeedStatus() {
    const container = document.getElementById("feed-status");
    if (!container) return;

    container.innerHTML = state.feedStatus.length ? state.feedStatus.map((feed, index) => `
        <div class="feed-item clickable" data-incident-type="feed" data-incident-index="${index}">
            <div>
                <strong>${feed.name}</strong>
                <span>${feed.description}</span>
                <small>${feed.records} records · ${freshnessText(feed)}</small>
            </div>
            <em class="feed-pill ${stateClass(feed)}">${displayState(feed)}</em>
        </div>
    `).join("") : emptyState("FEED STATUS WAITING");
    renderPanelStatuses();
}

function renderSensorHealth() {
    const health = state.opsHealth || {};
    const sensor = health.sensors?.[0];
    const heartbeat = sensor?.last_seen || sensor?.lastSeen;
    const heartbeatAge = heartbeat ? Date.now() - new Date(heartbeat).getTime() : Infinity;
    const sensorLive = Number.isFinite(heartbeatAge) && heartbeatAge <= 5 * 60 * 1000;
    const localNodes = state.attacks.filter(item => item.sourceKind === "local_sensor").length * 2;
    const globalNodes = state.attacks.filter(item => item.sourceKind !== "local_sensor").length * 2;
    const dbState = health.database?.status === "online" ? "ONLINE" : "UNKNOWN";
    const apiLatency = Number.isFinite(Number(health.apiLatencyMs)) ? `${health.apiLatencyMs} MS` : "UNKNOWN";

    text("health-sensor-name", sensor?.source || sensor?.sensor_id || "NO SENSOR");
    text("health-last-seen", heartbeat ? formatRelativeTime(heartbeat) : "NEVER");
    text("health-event-count", sensor?.event_count ?? sensor?.eventCount ?? 0);
    text("health-local-count", localNodes);
    text("health-global-count", globalNodes);
    text("health-api-state", `${dbState} · ${apiLatency}`);

    const status = document.getElementById("sensor-health-status");
    if (status) {
        status.textContent = sensorLive ? "LIVE" : "OFFLINE";
        status.className = `panel-state ${sensorLive ? "live" : "offline"}`;
        status.title = heartbeat ? `Last heartbeat ${formatTimestamp(heartbeat)}` : "No sensor heartbeat received";
    }
}

function renderAlerts() {
    const container = document.getElementById("alert-list");
    if (!container) return;

    container.innerHTML = state.alerts.length ? state.alerts.map((alert, index) => `
        <div class="alert-item clickable" data-incident-type="alert" data-incident-index="${index}">
            <div>
                <strong>${alert.title}</strong>
                <span>${alert.description}</span>
            </div>
            <em class="alert-severity ${alert.severity}">${alert.severity}</em>
        </div>
    `).join("") : emptyState("NO ACTIVE RULES");
}

function renderAssets() {
    const container = document.getElementById("asset-list");
    if (!container) return;
    text("asset-count", `${state.assets.length} ASSETS`);
    if (!state.assets.length) {
        container.innerHTML = '<small class="asset-empty">NO ASSETS REGISTERED</small>';
        return;
    }
    container.innerHTML = state.assets.slice(0, 8).map(asset => `
        <div class="asset-item">
            <div>
                <strong>${asset.name}</strong>
                <span>${asset.asset_type.replaceAll("_", " ")} · ${asset.ip_address || asset.domain || "no address"}</span>
            </div>
            <em class="asset-criticality ${asset.criticality}">${asset.criticality}</em>
        </div>
    `).join("");
}

function renderIncidents() {
    const container = document.getElementById("incident-list");
    if (!container) return;
    if (!state.incidents.length) {
        container.innerHTML = `
            <div class="incident-empty">
                <strong>NO LOCAL INCIDENTS</strong>
                <span>Awaiting correlated sensor evidence</span>
                <small>SURICATA · ZEEK · WAZUH · SYSLOG</small>
            </div>
        `;
        return;
    }
    container.innerHTML = state.incidents.slice(0, 6).map((incident, index) => `
        <div class="incident-item clickable" data-incident-type="incident" data-incident-index="${index}">
            <div>
                <strong>${incident.title}</strong>
                <span>${incident.event_count} events · ${incident.technique_id || "unclassified"} · ${incident.confidence}% confidence</span>
                <small>${formatRelativeTime(incident.last_seen)} · ${incident.source_ip || "unknown source"}</small>
            </div>
            <em class="incident-severity ${incident.severity}">${incident.severity}</em>
        </div>
    `).join("");
}

async function registerAsset(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const payload = Object.fromEntries(new FormData(form).entries());
    const response = await fetch("/api/assets", {
        method: "POST",
        headers: mutationHeaders(),
        body: JSON.stringify(payload),
    });
    if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.error || "Asset registration failed");
    }
    form.reset();
    await loadDashboard();
}

function renderAiSummary() {
    if (!state.aiSummary) return;

    text("assessment-state", state.aiSummary.assessment);
    text("assessment-score", `${Number(state.aiSummary.score || 0).toFixed(1)} / 10`);
    text("assessment-copy", state.aiSummary.posture);

    const actions = document.getElementById("ai-actions");
    if (actions) {
        actions.innerHTML = [
            ...state.aiSummary.drivers.slice(0, 2),
            ...state.aiSummary.actions.slice(0, 2),
        ].map(item => `<li>${item}</li>`).join("");
    }
}

function incidentActions(type) {
    const actions = {
        cve: [
            "Check asset inventory for affected vendor/product.",
            "Prioritize patching or mitigation if exposed externally.",
            "Create ticket for validation and owner assignment.",
        ],
        ransomware: [
            "Review sector and country exposure.",
            "Check for matching vendor/customer risk.",
            "Increase monitoring for related group indicators.",
        ],
        event: [
            "Validate source feed freshness.",
            "Correlate with CVE, malware, and ransomware panels.",
            "Escalate if repeated high severity events appear.",
        ],
        feed: [
            "Confirm source is syncing successfully.",
            "Investigate if records remain stale or quiet for too long.",
            "Review API keys/rate limits before production deployment.",
        ],
        alert: [
            "Assign owner and validate the triggering evidence.",
            "Correlate with asset exposure and current patch status.",
            "Escalate if the rule remains active after refresh.",
        ],
        incident: [
            "Validate the evidence against the affected asset.",
            "Review related endpoint and network logs.",
            "Contain or block only after analyst confirmation.",
        ],
    };
    return actions[type] || actions.event;
}

function openIncidentDrawer(type, item) {
    const drawer = document.getElementById("incident-drawer");
    if (!drawer || !item) return;

    const title = item.id || item.victim || item.title || item.name || "Incident";
    const severity = item.severity || item.status || "info";
    const source = item.source || item.source_ip || item.vendor || item.group || item.name || "Cyberwatch";
    const description = item.summary || item.description || item.title || item.product || "No description available.";

    text("drawer-type", type.toUpperCase());
    text("drawer-title", title);
    text("drawer-description", description);
    state.activeIncidentId = type === "incident" ? item.id : null;

    const controls = document.getElementById("incident-controls");
    if (controls) controls.hidden = type !== "incident";

    const meta = document.getElementById("drawer-meta");
    if (meta) {
        const network = item.enrichment?.source || {};
        const abuse = network.abuse || {};
        const metaItems = [
            ["Source", source],
            ["Scope", item.scope || (item.sourceKind === "local_sensor" ? "LOCAL DETECTION" : "GLOBAL INTELLIGENCE")],
            ["Severity", String(severity).toUpperCase()],
            ["Confidence", item.confidence ? `${item.confidence}%` : (item.records ?? item.cvss ?? item.country ?? "n/a")],
            ["Technique", item.technique_id ? `${item.technique_id} ${item.technique_name || ""}` : "n/a"],
            ["Geo", network.country && network.country !== "Unknown" ? `${network.country} (${network.locationSource || "unknown"})` : "unavailable"],
            ["ASN / ISP", network.asn || network.isp || "unavailable"],
            ["Abuse", abuse.status === "checked" ? `${abuse.score ?? 0} / 100` : (abuse.status || "unavailable")],
            ["Last Seen", formatRelativeTime(item.last_seen || item.createdAt || item.published || item.discovered || item.lastSync)],
        ];
        meta.innerHTML = metaItems.map(([label, value]) => `
            <div><span>${label}</span><strong>${value}</strong></div>
        `).join("");
    }

    const actions = document.getElementById("drawer-actions");
    if (actions) {
        const recommendations = Array.isArray(item.recommendations) ? item.recommendations : [];
        const actionItems = recommendations.length
            ? recommendations
            : item.recommendation
                ? [item.recommendation, ...incidentActions(type).slice(0, 2)]
            : incidentActions(type);
        actions.innerHTML = actionItems.map(action => `<li>${action}</li>`).join("");
    }

    const evidence = document.getElementById("drawer-evidence");
    if (evidence) {
        evidence.innerHTML = (Array.isArray(item.evidence) ? item.evidence : ["Evidence is collected from the connected feed."])
            .map(entry => `<li>${entry}</li>`).join("");
    }

    if (type === "incident") {
        populateIncidentControls(item);
        loadIncidentDetail(item.id).catch(error => console.error("Incident detail load failed", error));
    }

    drawer.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");
}

function populateIncidentControls(item) {
    const status = document.getElementById("incident-status");
    const assigned = document.getElementById("incident-assigned");
    const notes = document.getElementById("incident-notes");
    const closure = document.getElementById("incident-closure");
    if (status) status.value = item.status || "new";
    if (assigned) assigned.value = item.assigned_to || "";
    if (notes) notes.value = item.notes || "";
    if (closure) closure.value = item.closure_reason || "";
    renderIncidentActivity(item);
}

function renderIncidentActivity(item) {
    const comments = document.getElementById("incident-comments");
    const timeline = document.getElementById("incident-timeline");
    if (comments) comments.innerHTML = (item.comments || []).map(comment =>
        `<div class="activity-item"><strong>${comment.author}</strong><span>${formatRelativeTime(comment.createdAt)}</span><p>${comment.body}</p></div>`
    ).join("") || `<div class="activity-empty">No analyst comments.</div>`;
    if (timeline) timeline.innerHTML = (item.timeline || []).map(event =>
        `<div class="activity-item"><strong>${event.type.replaceAll("_", " ")}</strong><span>${formatRelativeTime(event.createdAt)}</span><p>${event.message}</p></div>`
    ).join("") || `<div class="activity-empty">No timeline entries.</div>`;
    const ai = document.getElementById("incident-ai-result");
    if (ai) {
        const result = item.ai_analysis || {};
        ai.innerHTML = result.conclusion
            ? `<strong>${result.assessment || "AI ANALYSIS"}</strong><p>${result.conclusion}</p><small>Provider: ${result.provider || "unknown"} · Confidence: ${result.confidence}% · Evidence: ${(result.evidenceReferences || []).join(", ") || "none"}</small>`
            : "";
    }
    const actions = document.getElementById("response-action-list");
    if (actions) actions.innerHTML = (item.responseActions || []).map(action =>
        `<div class="activity-item"><strong>${action.action_type}</strong><span>${action.status}</span><p>${action.target} · ${action.requested_by}</p>${action.status === "pending_approval" ? `<button type="button" data-approve-action="${action.id}">APPROVE</button>` : ""}</div>`
    ).join("") || `<div class="activity-empty">No response actions requested.</div>`;
}

async function loadIncidentDetail(id) {
    const detail = await getJson(`/api/incidents/${id}`);
    const index = state.incidents.findIndex(item => item.id === id);
    if (index >= 0) state.incidents[index] = detail;
    if (state.activeIncidentId === id) populateIncidentControls(detail);
}

async function saveIncident() {
    if (!state.activeIncidentId) return;
    const payload = {
        status: document.getElementById("incident-status")?.value,
        assigned_to: document.getElementById("incident-assigned")?.value,
        notes: document.getElementById("incident-notes")?.value,
        closure_reason: document.getElementById("incident-closure")?.value,
    };
    const response = await fetch(`/api/incidents/${state.activeIncidentId}`, {
        method: "PATCH", headers: mutationHeaders(), body: JSON.stringify(payload),
    });
    if (!response.ok) throw new Error((await response.json()).error || "Incident update failed");
    const detail = await response.json();
    const index = state.incidents.findIndex(item => item.id === detail.id);
    if (index >= 0) state.incidents[index] = detail;
    populateIncidentControls(detail);
    renderIncidents();
}

async function addIncidentComment() {
    if (!state.activeIncidentId) return;
    const input = document.getElementById("incident-comment-input");
    const body = input?.value.trim();
    if (!body) return;
    const response = await fetch(`/api/incidents/${state.activeIncidentId}/comments`, {
        method: "POST", headers: mutationHeaders(), body: JSON.stringify({ body, author: "analyst" }),
    });
    if (!response.ok) throw new Error((await response.json()).error || "Comment failed");
    input.value = "";
    const detail = await response.json();
    const index = state.incidents.findIndex(item => item.id === detail.id);
    if (index >= 0) state.incidents[index] = detail;
    populateIncidentControls(detail);
}

async function runIncidentAi() {
    if (!state.activeIncidentId) return;
    const response = await fetch(`/api/incidents/${state.activeIncidentId}/ai-analysis`, { method: "POST", headers: mutationHeaders() });
    if (!response.ok) throw new Error("AI analysis failed");
    const result = await response.json();
    const incident = state.incidents.find(item => item.id === state.activeIncidentId);
    if (incident) { incident.ai_analysis = result; renderIncidentActivity(incident); }
}

async function notifyIncident() {
    if (!state.activeIncidentId) return;
    const response = await fetch(`/api/incidents/${state.activeIncidentId}/notify`, { method: "POST", headers: mutationHeaders() });
    if (!response.ok) throw new Error("Alert delivery failed");
    const detail = await getJson(`/api/incidents/${state.activeIncidentId}`);
    const index = state.incidents.findIndex(item => item.id === detail.id);
    if (index >= 0) state.incidents[index] = detail;
    populateIncidentControls(detail);
}

async function requestResponseAction() {
    if (!state.activeIncidentId) return;
    const target = document.getElementById("response-action-target")?.value.trim();
    if (!target) return;
    const response = await fetch(`/api/incidents/${state.activeIncidentId}/response-actions`, {
        method: "POST", headers: mutationHeaders(),
        body: JSON.stringify({ action_type: document.getElementById("response-action-type")?.value, target, requested_by: "analyst" }),
    });
    if (!response.ok) throw new Error((await response.json()).error || "Response request failed");
    document.getElementById("response-action-target").value = "";
    const detail = await getJson(`/api/incidents/${state.activeIncidentId}`);
    const index = state.incidents.findIndex(item => item.id === detail.id);
    if (index >= 0) state.incidents[index] = detail;
    populateIncidentControls(detail);
}

async function approveResponseAction(actionId) {
    const response = await fetch(`/api/response-actions/${actionId}/approve`, {
        method: "POST", headers: mutationHeaders(), body: JSON.stringify({ approved_by: "analyst" }),
    });
    if (!response.ok) throw new Error((await response.json()).error || "Approval failed");
    const detail = await getJson(`/api/incidents/${state.activeIncidentId}`);
    const index = state.incidents.findIndex(item => item.id === detail.id);
    if (index >= 0) state.incidents[index] = detail;
    populateIncidentControls(detail);
}

function closeIncidentDrawer() {
    const drawer = document.getElementById("incident-drawer");
    if (!drawer) return;
    drawer.classList.remove("open");
    drawer.setAttribute("aria-hidden", "true");
}

function handleIncidentClick(event) {
    const row = event.target.closest("[data-incident-type]");
    if (!row) return;

    const type = row.dataset.incidentType;
    const index = Number(row.dataset.incidentIndex);
    const collections = {
        cve: state.cves,
        ransomware: state.ransomware,
        event: state.combinedEvents || state.events,
        feed: state.feedStatus,
        alert: state.alerts,
        incident: state.incidents,
    };
    openIncidentDrawer(type, collections[type]?.[index]);
}

function renderRiskRings() {
    const container = document.getElementById("risk-rings");
    if (!container) return;

    const rings = [
        ["Memcache", 69.24, "#55baff"],
        ["WannaMine", 19.84, "#ff786c"],
        ["WannaCry", 56.83, "#ff8fa3"],
        ["GlobeImposter", 89.26, "#5fffe0"],
        ["Others", 24.08, "#9b5cff"],
    ];

    container.innerHTML = rings.map(([label, value, color]) => `
        <div class="risk-ring">
            <div class="ring-gauge" style="--value:${value};--ring-color:${color}">
                <strong>${value.toFixed(2)}%</strong>
            </div>
            <span>${label}</span>
        </div>
    `).join("");
}

function threatColor(type, severity) {
    const value = String(type || "").toLowerCase();
    if (value.includes("ransom") || value.includes("malware")) return "#ff4747";
    if (value.includes("outage") || value.includes("power")) return "#ffb21a";
    if (value.includes("hijack") || value.includes("bgp")) return "#9b5cff";
    if (value.includes("mdns")) return "#9b5cff";
    if (value.includes("dns")) return "#55baff";
    if (value.includes("flow") || value.includes("conn")) return "#3f83ff";
    if (value.includes("scan") || value.includes("recon") || value.includes("probe")) return "#3f83ff";
    if (value.includes("exploit") || value.includes("cve") || value.includes("kev") || value.includes("intrusion") || value.includes("endpoint") || value.includes("zeek")) return "#23ce73";
    const level = String(severity || "").toLowerCase();
    if (level.includes("critical")) return "#ff4747";
    if (level.includes("high")) return "#ffb21a";
    if (level.includes("medium")) return "#3f83ff";
    if (level.includes("low") || level.includes("info")) return "#23ce73";
    return "#55baff";
}

function projectGlobePoint(lat, lng, radius, rotation) {
    const phi = (90 - Number(lat)) * Math.PI / 180;
    const theta = (Number(lng) + rotation + 180) * Math.PI / 180;
    return {
        x: radius * Math.sin(phi) * Math.cos(theta),
        y: radius * Math.cos(phi),
        z: radius * Math.sin(phi) * Math.sin(theta),
    };
}

function drawVisiblePolyline(ctx, points, centerX, centerY, radius, rotation) {
    ctx.beginPath();
    let started = false;
    points.forEach(([lat, lng]) => {
        const p = projectGlobePoint(lat, lng, radius, rotation);
        if (p.z < 0) {
            started = false;
            return;
        }
        if (!started) {
            ctx.moveTo(centerX + p.x, centerY - p.y);
            started = true;
        } else {
            ctx.lineTo(centerX + p.x, centerY - p.y);
        }
    });
    ctx.stroke();
}

function drawCountryLayer(ctx, centerX, centerY, radius, rotation) {
    ctx.save();
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
    ctx.clip();

    ctx.strokeStyle = "rgba(90, 225, 210, 0.34)";
    ctx.lineWidth = 1.1;
    countryOutlines.forEach(points => drawVisiblePolyline(ctx, points, centerX, centerY, radius, rotation));

    ctx.fillStyle = "rgba(180, 244, 255, 0.7)";
    ctx.font = "10px Courier New";
    ctx.textAlign = "center";
    countryLabels.forEach(label => {
        const p = projectGlobePoint(label.lat, label.lng, radius, rotation);
        if (p.z < radius * 0.12) return;
        ctx.globalAlpha = Math.min(0.9, 0.35 + p.z / radius);
        ctx.fillText(label.code, centerX + p.x, centerY - p.y);
    });
    ctx.globalAlpha = 1;
    ctx.restore();
}

function renderGlobe() {
    state.liveThreats = state.attacks.flatMap(attack => [
        {
            lat: attack.sourceLat,
            lng: attack.sourceLng,
            type: attack.category,
            color: threatColor(attack.category, attack.severity),
            born: Date.now() - Math.random() * 3000,
            life: 9000 + Math.random() * 6000,
            arc: attack,
            sourceKind: attack.sourceKind || "global_intelligence",
        },
        {
            lat: attack.targetLat,
            lng: attack.targetLng,
            type: attack.category,
            color: threatColor(attack.category, attack.severity),
            born: Date.now() - Math.random() * 3000,
            life: 9000 + Math.random() * 6000,
            arc: attack,
            sourceKind: attack.sourceKind || "global_intelligence",
        },
    ]);

    const localCount = state.liveThreats.filter(threat => threat.sourceKind === "local_sensor").length;
    const globalCount = state.liveThreats.length - localCount;
    text("local-node-count", localCount);
    text("global-node-count", globalCount);
}

function updateGlobeFrame() {
    const canvas = document.getElementById("threat-globe");
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    const width = canvas.width;
    const height = canvas.height;
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(width, height) * 0.34;
    const now = Date.now();

    state.rotation = ((now - state.startedAt) / 85) % 360;

    ctx.clearRect(0, 0, width, height);
    const bg = ctx.createRadialGradient(centerX, centerY, radius * 0.08, centerX, centerY, radius * 1.18);
    bg.addColorStop(0, "#0c2630");
    bg.addColorStop(0.62, "#06121a");
    bg.addColorStop(1, "#020609");
    ctx.fillStyle = bg;
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius + 5, 0, Math.PI * 2);
    ctx.fill();

    ctx.save();
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
    ctx.clip();
    ctx.strokeStyle = "rgba(85, 186, 255, 0.18)";
    ctx.lineWidth = 0.7;

    for (let lat = -75; lat <= 75; lat += 15) {
        ctx.beginPath();
        let started = false;
        for (let lng = -180; lng <= 180; lng += 4) {
            const p = projectGlobePoint(lat, lng, radius, state.rotation);
            if (p.z < 0) {
                started = false;
                continue;
            }
            if (!started) {
                ctx.moveTo(centerX + p.x, centerY - p.y);
                started = true;
            } else {
                ctx.lineTo(centerX + p.x, centerY - p.y);
            }
        }
        ctx.stroke();
    }

    for (let lng = 0; lng < 360; lng += 20) {
        ctx.beginPath();
        let started = false;
        for (let lat = -90; lat <= 90; lat += 4) {
            const p = projectGlobePoint(lat, lng, radius, state.rotation);
            if (p.z < 0) {
                started = false;
                continue;
            }
            if (!started) {
                ctx.moveTo(centerX + p.x, centerY - p.y);
                started = true;
            } else {
                ctx.lineTo(centerX + p.x, centerY - p.y);
            }
        }
        ctx.stroke();
    }
    ctx.restore();

    drawCountryLayer(ctx, centerX, centerY, radius, state.rotation);

    state.liveThreats.forEach(threat => {
        const age = now - threat.born;
        if (age > threat.life) {
            threat.born = now;
            threat.lat = Math.random() * 150 - 75;
            threat.lng = Math.random() * 360 - 180;
        }

        const p = projectGlobePoint(threat.lat, threat.lng, radius, state.rotation);
        const isFrontSide = p.z >= 0;

        const opacity = Math.max(0.18, 1 - age / threat.life);
        const pulse = 0.5 + 0.5 * Math.sin(now / 180);
        const depthOpacity = isFrontSide ? 1 : 0.2;
        ctx.globalAlpha = opacity * depthOpacity;
        const isLocalSensor = threat.sourceKind === "local_sensor";
        ctx.fillStyle = threat.color;
        ctx.beginPath();
        ctx.arc(centerX + p.x, centerY - p.y, isFrontSide ? (isLocalSensor ? 4.5 : 3.2) : 2.1, 0, Math.PI * 2);
        ctx.fill();

        if (isLocalSensor && isFrontSide) {
            ctx.globalAlpha = opacity * 0.9;
            ctx.strokeStyle = "#ffffff";
            ctx.lineWidth = 1.2;
            ctx.beginPath();
            ctx.arc(centerX + p.x, centerY - p.y, 6.5, 0, Math.PI * 2);
            ctx.stroke();
        }

        ctx.globalAlpha = opacity * depthOpacity * 0.42;
        ctx.strokeStyle = threat.color;
        ctx.beginPath();
        ctx.arc(centerX + p.x, centerY - p.y, isFrontSide ? 7 + pulse * 5 : 3.5, 0, Math.PI * 2);
        ctx.stroke();
        ctx.globalAlpha = 1;
    });

    ctx.strokeStyle = "rgba(85, 186, 255, 0.56)";
    ctx.lineWidth = 1.4;
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
    ctx.stroke();

    const orbitLat = 18 + Math.sin(now / 5000) * 38;
    const orbitLng = (((now - state.startedAt) / 120) % 360) - 180;
    text("position-readout", `${orbitLat.toFixed(2)}, ${orbitLng.toFixed(2)}`);
}

function animateGlobe() {
    updateGlobeFrame();
    requestAnimationFrame(animateGlobe);
}

function updateLiveTelemetry() {
    const solar = state.liveFeeds?.solar;
    if (solar) {
        text("solar-wind", `${solar.windSpeed} km/s`);
        text("solar-density", `${solar.density} /cc`);
        text("solar-bt", `${solar.bt} nT`);
        text("solar-kp", `${solar.kp}`);
        text("solar-freshness", solar.updatedAt
            ? `OBSERVED ${formatTimestamp(solar.updatedAt)} · checked ${formatRelativeTime(solar.checkedAt)}`
            : `NO LIVE OBSERVATION · checked ${formatRelativeTime(solar.checkedAt)}`);
    }
    drawLiveCharts();
    renderFeedStatus();
    renderSummary();
}

function drawTrend() {
    const canvas = document.getElementById("threat-chart");
    if (!canvas || !state.trend.length) return;

    const ctx = canvas.getContext("2d");
    const width = canvas.width;
    const height = canvas.height;
    const padding = 32;
    const max = Math.max(...state.trend.map(item => item.count), 1);

    ctx.clearRect(0, 0, width, height);
    ctx.strokeStyle = "rgba(85, 186, 255, 0.18)";
    ctx.lineWidth = 1;

    for (let i = 0; i < 5; i += 1) {
        const y = padding + ((height - padding * 2) / 4) * i;
        ctx.beginPath();
        ctx.moveTo(padding, y);
        ctx.lineTo(width - padding, y);
        ctx.stroke();
    }

    const points = state.trend.map((item, index) => ({
        x: padding + ((width - padding * 2) / (state.trend.length - 1)) * index,
        y: height - padding - (item.count / max) * (height - padding * 2),
        item,
    }));

    ctx.beginPath();
    points.forEach((point, index) => index ? ctx.lineTo(point.x, point.y) : ctx.moveTo(point.x, point.y));
    ctx.lineTo(points[points.length - 1].x, height - padding);
    ctx.lineTo(points[0].x, height - padding);
    ctx.closePath();
    const area = ctx.createLinearGradient(0, padding, 0, height - padding);
    area.addColorStop(0, "rgba(85, 186, 255, 0.22)");
    area.addColorStop(1, "rgba(85, 186, 255, 0)");
    ctx.fillStyle = area;
    ctx.fill();

    ctx.beginPath();
    points.forEach((point, index) => index ? ctx.lineTo(point.x, point.y) : ctx.moveTo(point.x, point.y));
    ctx.strokeStyle = "#55baff";
    ctx.lineWidth = 3;
    ctx.stroke();

    points.forEach(point => {
        ctx.fillStyle = "#030609";
        ctx.strokeStyle = "#55baff";
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(point.x, point.y, 5, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
        ctx.fillStyle = "#52627a";
        ctx.font = "12px Courier New";
        ctx.fillText(point.item.day, point.x - 12, height - 8);
    });

    const latest = points[points.length - 1];
    ctx.fillStyle = "#55baff";
    ctx.beginPath();
    ctx.arc(latest.x, latest.y, 3, 0, Math.PI * 2);
    ctx.fill();
}

function drawMiniChart(id, values, color) {
    const canvas = document.getElementById(id);
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const width = canvas.width;
    const height = canvas.height;
    ctx.clearRect(0, 0, width, height);
    ctx.strokeStyle = "rgba(85, 186, 255, 0.12)";
    ctx.beginPath();
    ctx.moveTo(0, height - 16);
    ctx.lineTo(width, height - 16);
    ctx.stroke();
    if (!values.length) {
        ctx.fillStyle = "#52627a";
        ctx.font = "10px Courier New";
        ctx.fillText("NO OBSERVATION", 8, height / 2);
        return;
    }
    const min = Math.min(...values);
    const max = Math.max(...values, min + 1);
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    values.forEach((value, index) => {
        const x = values.length === 1 ? width / 2 : (width / (values.length - 1)) * index;
        const y = height - 18 - ((value - min) / (max - min)) * (height - 30);
        if (index === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.lineTo(width, height - 16);
    ctx.lineTo(0, height - 16);
    ctx.closePath();
    const area = ctx.createLinearGradient(0, 0, 0, height);
    area.addColorStop(0, `${color}33`);
    area.addColorStop(1, `${color}00`);
    ctx.fillStyle = area;
    ctx.fill();

    ctx.beginPath();
    values.forEach((value, index) => {
        const x = values.length === 1 ? width / 2 : (width / (values.length - 1)) * index;
        const y = height - 18 - ((value - min) / (max - min)) * (height - 30);
        if (index === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    });
    ctx.stroke();

    const lastValue = values[values.length - 1];
    const lastX = values.length === 1 ? width / 2 : width;
    const lastY = height - 18 - ((lastValue - min) / (max - min)) * (height - 30);
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(lastX, lastY, 3, 0, Math.PI * 2);
    ctx.fill();
}

function drawLiveCharts() {
    const wind = Number(state.liveFeeds?.solar?.windSpeed);
    if (Number.isFinite(wind)) {
        state.telemetryHistory.push(wind);
        state.telemetryHistory = state.telemetryHistory.slice(-36);
        text("solar-chart-value", `${wind} km/s`);
    }
    const activity = state.attacks.length + state.incidents.length;
    state.sensorHistory.push(activity);
    state.sensorHistory = state.sensorHistory.slice(-36);
    text("sensor-chart-value", `${activity} signals`);
    drawMiniChart("solar-chart", state.telemetryHistory, "#ffb21a");
    drawMiniChart("sensor-chart", state.sensorHistory, "#55baff");
}

async function loadDashboard() {
    const [summary, trend, cves, ransomware, attacks, events, industries, feedStatus, aiSummary, alerts, liveFeeds, assets, incidents, opsHealth] = await Promise.all([
        safeJson("/api/summary", { criticalCves: 0, activeExploits: 0, threatActors: 0, victims: 0, activeAttacks: 0, threatScore: 0, assessment: "WAITING" }),
        safeJson("/api/threat-trend", []),
        safeJson("/api/cves", []),
        safeJson("/api/ransomware", []),
        safeJson("/api/attacks", []),
        safeJson("/api/events", []),
        safeJson("/api/industries", []),
        safeJson("/api/feed-status", []),
        safeJson("/api/ai-summary", { posture: "Waiting for intelligence", score: 0, assessment: "WAITING", drivers: [], actions: [] }),
        safeJson("/api/alerts", []),
        safeJson("/api/live-feeds", { solar: null, bgp: { items: [] }, outages: { items: [] } }),
        safeJson("/api/assets", []),
        safeJson("/api/incidents", []),
        safeJson("/api/ops/health", { status: "degraded", database: { status: "unknown" }, sensors: [] }),
    ]);

    Object.assign(state, { summary, trend, cves, ransomware, attacks, events, industries, feedStatus, aiSummary, alerts, liveFeeds, assets, incidents, opsHealth });
    renderSummary();
    renderCves();
    renderRansomware();
    renderEvents();
    renderIndustries();
    renderFeedStatus();
    renderAlerts();
    renderAssets();
    renderIncidents();
    renderLiveFeedTables();
    renderAiSummary();
    renderRiskRings();
    renderGlobe();
    renderSensorHealth();
    drawTrend();
}

async function refreshFeeds() {
    const button = document.getElementById("refresh-button");
    if (button) button.textContent = "SYNCING";
    try {
        await fetch("/api/refresh", { method: "POST", headers: mutationHeaders() });
        await loadDashboard();
    } finally {
        if (button) button.textContent = "REFRESH";
    }
}

window.addEventListener("resize", drawTrend);
document.addEventListener("DOMContentLoaded", () => {
    renderClocks();
    loadDashboard().catch(error => console.error("Dashboard load failed", error));
    startEventStream();
    animateGlobe();
    setInterval(updateGlobeFrame, 80);
    updateLiveTelemetry();
    logLiveEvent("exploit", "Dashboard initialized - backend feed monitor active");
    setInterval(renderClocks, 1000);
    setInterval(updateLiveTelemetry, 1000);
    setInterval(() => loadDashboard().catch(console.error), 30000);
    setInterval(() => refreshFeeds().catch(console.error), 120000);
    document.getElementById("refresh-button")?.addEventListener("click", refreshFeeds);
    document.getElementById("asset-form")?.addEventListener("submit", event => registerAsset(event).catch(console.error));
    document.body.addEventListener("click", handleIncidentClick);
    document.getElementById("drawer-close")?.addEventListener("click", closeIncidentDrawer);
    document.getElementById("incident-save")?.addEventListener("click", () => saveIncident().catch(console.error));
    document.getElementById("incident-comment-submit")?.addEventListener("click", () => addIncidentComment().catch(console.error));
    document.getElementById("incident-ai")?.addEventListener("click", () => runIncidentAi().catch(console.error));
    document.getElementById("incident-notify")?.addEventListener("click", () => notifyIncident().catch(console.error));
    document.getElementById("response-action-submit")?.addEventListener("click", () => requestResponseAction().catch(console.error));
    document.body.addEventListener("click", event => {
        const action = event.target.closest("[data-approve-action]");
        if (action) approveResponseAction(action.dataset.approveAction).catch(console.error);
    });
});
