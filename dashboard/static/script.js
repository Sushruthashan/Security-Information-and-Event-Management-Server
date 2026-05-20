const API_BASE = "";

async function fetchLogs() {

  try {

    const response = await fetch(`${API_BASE}/logs`);

    const logs = await response.json();

    renderLogs(logs);

  } catch(error) {

    console.error("Failed to fetch logs:", error);

  }
}

async function fetchAlerts() {

  try {

    const response = await fetch(`${API_BASE}/alerts`);

    const alerts = await response.json();

    renderAlerts(alerts);

  } catch(error) {

    console.error("Failed to fetch alerts:", error);

  }
}

async function fetchHealth() {

  try {

    const response = await fetch(`${API_BASE}/health`);

    const health = await response.json();

    updateSystemHealth(health);

  } catch(error) {

    console.error("Failed to fetch health:", error);

  }
}

function renderLogs(logs) {

  const table = document.getElementById("logsTable");

  table.innerHTML = "";

  document.getElementById("totalLogs").innerText = logs.length;

  logs.forEach(log => {

    table.innerHTML += `
      <tr>
        <td>${log.timestamp || "-"}</td>
        <td>${log.hostname || "-"}</td>
        <td>${log.event_type || "-"}</td>
        <td>${log.process_name || "-"}</td>
      </tr>
    `;

  });
}

function renderAlerts(alerts) {

  const container = document.getElementById("alertsContainer");

  container.innerHTML = "";

  document.getElementById("totalAlerts").innerText = alerts.length;

  alerts.forEach(alert => {

    let severityClass = "low";

    const severity = (alert.severity || "").toUpperCase();

    if(severity === "CRITICAL" || severity === "HIGH") {

      severityClass = "high";

    }
    else if(severity === "MEDIUM") {

      severityClass = "medium";

    }

    container.innerHTML += `

      <div class="alert">

        <div>
          <p><strong>${alert.type}</strong></p>
          <p>Endpoint: ${alert.endpoint}</p>
          <p>Process: ${alert.process}</p>
        </div>

        <div>
          <span class="severity ${severityClass}">
            ${alert.severity}
          </span>
        </div>

      </div>

    `;

  });
}

function updateSystemHealth(health){

  document.getElementById("activeEndpoints").innerText =
    health.active_endpoints;

  document.getElementById("cpuText").innerText =
    `${health.cpu}%`;

  document.getElementById("memoryText").innerText =
    `${health.memory}%`;

  document.getElementById("cpuBar").style.width =
    `${health.cpu}%`;

  document.getElementById("memoryBar").style.width =
    `${health.memory}%`;
}

async function refreshDashboard(){

  await fetchLogs();
  await fetchAlerts();
  await fetchHealth();
}

setInterval(refreshDashboard, 5000);

refreshDashboard();
