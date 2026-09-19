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
    markerElements: [],
    liveThreats: [],
    startedAt: Date.now(),
    rotation: 0,
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

const bgpRows = [
    ["US", "Cloudflare", "104.16/12"],
    ["US", "Amazon AWS", "3.0/8"],
    ["US", "Microsoft", "20.0/14"],
    ["US", "Google LLC", "8.8/24"],
    ["SE", "Arelion", "62.115/16"],
    ["US", "Cogent", "38.0/8"],
];

const outageRows = [
    ["UA", "conflict", "active"],
    ["RU", "regime", "active"],
    ["MM", "regime", "active"],
    ["IR", "regime", "active"],
    ["SY", "conflict", "ended"],
    ["CN", "policy", "active"],
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

function renderStaticTables() {
    const bgp = document.getElementById("bgp-feed");
    const outages = document.getElementById("outage-feed");

    if (bgp) {
        bgp.innerHTML = bgpRows.map(row => `
            <div class="table-row">
                <span class="badge">${row[0]}</span>
                <span class="row-title">${row[1]}</span>
                <span class="row-meta">${row[2]}</span>
            </div>
        `).join("");
    }

    if (outages) {
        outages.innerHTML = outageRows.map(row => `
            <div class="table-row">
                <span class="badge">${row[0]}</span>
                <span class="row-title">${row[1]}</span>
                <span class="${row[2] === "active" ? "row-hot" : "row-meta"}">${row[2]}</span>
            </div>
        `).join("");
    }
}

function renderSummary() {
    const summary = state.summary;
    if (!summary) return;

    const pulse = Math.floor((Date.now() / 4000) % 3);
    text("critical-cves", summary.criticalCves + (pulse === 0 ? 1 : 0));
    text("active-exploits", summary.activeExploits + (pulse === 1 ? 1 : 0));
    text("threat-actors", summary.threatActors);
    text("victims", summary.victims);
    text("threat-score", liveThreatScore(summary.threatScore).toFixed(1));
    text("assessment-state", summary.assessment);
    text("assessment-score", `${liveThreatScore(summary.threatScore).toFixed(1)} / 10`);
    if (!state.aiSummary) {
        text("assessment-copy", `${summary.activeExploits} exploited vulnerabilities, ${summary.victims} ransomware victims, and ${summary.activeAttacks} active global markers are influencing the current risk posture.`);
    }
    text("feed-count", `${state.cves.length + state.ransomware.length + state.events.length} LIVE INTELLIGENCE FEEDS`);
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

    container.innerHTML = state.cves.map((cve, index) => `
        <div class="table-row clickable" data-incident-type="cve" data-incident-index="${index}">
            <span class="row-title">${cve.id}</span>
            <span>${cve.vendor} - ${cve.product}</span>
            <span class="${severityClass(cve.severity)}">${Number(cve.cvss || 0).toFixed(1)}</span>
        </div>
    `).join("");
}

function renderRansomware() {
    const container = document.getElementById("ransomware-feed");
    if (!container) return;

    container.innerHTML = state.ransomware.map((item, index) => `
        <div class="table-row clickable" data-incident-type="ransomware" data-incident-index="${index}">
            <span class="row-title">${item.victim}</span>
            <span class="red">${item.group}</span>
            <span class="badge">${item.country.slice(0, 2).toUpperCase()}</span>
        </div>
    `).join("");
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

    container.innerHTML = combinedEvents.map((event, index) => {
        const date = new Date(event.createdAt);
        const time = Number.isNaN(date.getTime()) ? "--:--" : date.toLocaleTimeString([], { hour12: false });
        return `
            <div class="event-item clickable" data-incident-type="event" data-incident-index="${index}">
                <time>${time}</time>
                <span>${event.title}</span>
            </div>
        `;
    }).join("");
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

    container.innerHTML = state.industries.map(item => `
        <div class="industry-item">
            <span>${item.name}</span>
            <strong>${item.count}</strong>
            <div class="bar"><span style="width:${(item.count / max) * 100}%"></span></div>
        </div>
    `).join("");
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

function renderFeedStatus() {
    const container = document.getElementById("feed-status");
    if (!container) return;

    container.innerHTML = state.feedStatus.map((feed, index) => `
        <div class="feed-item clickable" data-incident-type="feed" data-incident-index="${index}">
            <div>
                <strong>${feed.name}</strong>
                <span>${feed.description}</span>
                <small>${feed.records} records - ${formatRelativeTime(feed.lastSync)}</small>
            </div>
            <em class="feed-pill ${feed.status}">${feed.status}</em>
        </div>
    `).join("");
}

function renderAlerts() {
    const container = document.getElementById("alert-list");
    if (!container) return;

    container.innerHTML = state.alerts.map((alert, index) => `
        <div class="alert-item clickable" data-incident-type="alert" data-incident-index="${index}">
            <div>
                <strong>${alert.title}</strong>
                <span>${alert.description}</span>
            </div>
            <em class="alert-severity ${alert.severity}">${alert.severity}</em>
        </div>
    `).join("");
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
    };
    return actions[type] || actions.event;
}

function openIncidentDrawer(type, item) {
    const drawer = document.getElementById("incident-drawer");
    if (!drawer || !item) return;

    const title = item.id || item.victim || item.title || item.name || "Incident";
    const severity = item.severity || item.status || "info";
    const source = item.source || item.vendor || item.group || item.name || "Cyberwatch";
    const description = item.description || item.title || item.product || item.description || "No description available.";

    text("drawer-type", type.toUpperCase());
    text("drawer-title", title);
    text("drawer-description", description);

    const meta = document.getElementById("drawer-meta");
    if (meta) {
        const metaItems = [
            ["Source", source],
            ["Severity", String(severity).toUpperCase()],
            ["Records", item.records ?? item.cvss ?? item.country ?? "n/a"],
            ["Last Seen", formatRelativeTime(item.createdAt || item.published || item.discovered || item.lastSync)],
        ];
        meta.innerHTML = metaItems.map(([label, value]) => `
            <div><span>${label}</span><strong>${value}</strong></div>
        `).join("");
    }

    const actions = document.getElementById("drawer-actions");
    if (actions) {
        const actionItems = item.recommendation
            ? [item.recommendation, ...incidentActions(type).slice(0, 2)]
            : incidentActions(type);
        actions.innerHTML = actionItems.map(action => `<li>${action}</li>`).join("");
    }

    drawer.classList.add("open");
    drawer.setAttribute("aria-hidden", "false");
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

function threatColor(type) {
    const colors = {
        ransomware: "#ff4747",
        outage: "#ffb21a",
        hijack: "#9b5cff",
        scan: "#3f83ff",
        exploit: "#23ce73",
        eq: "#23ce73",
    };
    return colors[String(type || "").toLowerCase()] || "#55baff";
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
            color: threatColor(attack.category),
            born: Date.now() - Math.random() * 3000,
            life: 9000 + Math.random() * 6000,
            arc: attack,
        },
        {
            lat: attack.targetLat,
            lng: attack.targetLng,
            type: attack.category,
            color: threatColor(attack.category),
            born: Date.now() - Math.random() * 3000,
            life: 9000 + Math.random() * 6000,
            arc: attack,
        },
    ]);
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
        if (p.z < 0) return;

        const opacity = Math.max(0.18, 1 - age / threat.life);
        const pulse = 0.5 + 0.5 * Math.sin(now / 180);
        ctx.globalAlpha = opacity;
        ctx.fillStyle = threat.color;
        ctx.beginPath();
        ctx.arc(centerX + p.x, centerY - p.y, 3.2, 0, Math.PI * 2);
        ctx.fill();

        ctx.globalAlpha = opacity * 0.42;
        ctx.strokeStyle = threat.color;
        ctx.beginPath();
        ctx.arc(centerX + p.x, centerY - p.y, 7 + pulse * 5, 0, Math.PI * 2);
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
    const t = Date.now();
    text("solar-wind", `${Math.round(383 + Math.sin(t / 2300) * 18)} km/s`);
    text("solar-density", `${(9.6 + Math.sin(t / 3100) * 0.9).toFixed(1)} /cc`);
    text("solar-bt", `${(10.2 + Math.cos(t / 2700) * 1.4).toFixed(1)} nT`);
    text("solar-kp", `${(3.7 + Math.sin(t / 4500) * 0.5).toFixed(1)}`);
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
}

async function loadDashboard() {
    const [summary, trend, cves, ransomware, attacks, events, industries, feedStatus, aiSummary, alerts] = await Promise.all([
        getJson("/api/summary"),
        getJson("/api/threat-trend"),
        getJson("/api/cves"),
        getJson("/api/ransomware"),
        getJson("/api/attacks"),
        getJson("/api/events"),
        getJson("/api/industries"),
        getJson("/api/feed-status"),
        getJson("/api/ai-summary"),
        getJson("/api/alerts"),
    ]);

    Object.assign(state, { summary, trend, cves, ransomware, attacks, events, industries, feedStatus, aiSummary, alerts });
    renderSummary();
    renderCves();
    renderRansomware();
    renderEvents();
    renderIndustries();
    renderFeedStatus();
    renderAlerts();
    renderAiSummary();
    renderRiskRings();
    renderGlobe();
    drawTrend();
}

async function refreshFeeds() {
    const button = document.getElementById("refresh-button");
    if (button) button.textContent = "SYNCING";
    try {
        await fetch("/api/refresh", { method: "POST" });
        await loadDashboard();
    } finally {
        if (button) button.textContent = "REFRESH";
    }
}

window.addEventListener("resize", drawTrend);
document.addEventListener("DOMContentLoaded", () => {
    renderClocks();
    renderStaticTables();
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
    document.body.addEventListener("click", handleIncidentClick);
    document.getElementById("drawer-close")?.addEventListener("click", closeIncidentDrawer);
});
