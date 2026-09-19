// =========================
// LIVE CYBER ALERTS
// =========================

const alerts = [

    "🔴 New Critical CVE Detected",
    "🟠 New Ransomware Victim",
    "🟡 Exploit Released",
    "🔵 Threat Actor Activity",
    "🟢 Phishing Campaign Alert",
    "🟣 Malware Campaign Active",
    "⚠️ Zero-Day Under Investigation"

];

function updateTicker(){

    const ticker =
        document.querySelector(".ticker");

    if(!ticker) return;

    const randomAlert =
        alerts[Math.floor(
            Math.random()*alerts.length
        )];

    ticker.innerHTML =
        randomAlert +
        " | Updated: " +
        new Date().toLocaleTimeString();
}

setInterval(updateTicker,5000);


// =========================
// LIVE CARD UPDATES
// =========================

function randomStats(){

    const cves =
        document.getElementById("critical-cves");

    const exploits =
        document.getElementById("active-exploits");

    const actors =
        document.getElementById("threat-actors");

    const victims =
        document.getElementById("victims");

    if(cves)
        cves.innerText =
        50 + Math.floor(Math.random()*20);

    if(exploits)
        exploits.innerText =
        20 + Math.floor(Math.random()*20);

    if(actors)
        actors.innerText =
        10 + Math.floor(Math.random()*20);

    if(victims)
        victims.innerText =
        5 + Math.floor(Math.random()*20);
}

setInterval(randomStats,10000);
