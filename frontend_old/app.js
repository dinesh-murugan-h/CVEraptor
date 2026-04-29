const API_BASE = "http://127.0.0.1:8000";

let lastCve = null;
let lastData = null;

async function searchCVE() {
  const input = document.getElementById("cveInput");
  const cveId = input.value.trim().toUpperCase();

  if (!cveId) {
    alert("Enter a CVE ID.");
    return;
  }

  lastCve = cveId;
  const results = document.getElementById("results");
  results.innerHTML = `<div class="loading">Loading ${cveId}...</div>`;

  try {
    const response = await fetch(`${API_BASE}/api/cve/${cveId}`);

    if (!response.ok) {
      throw new Error(`Backend returned HTTP ${response.status}`);
    }

    const data = await response.json();
    lastData = data;
    renderResult(data);
  } catch (error) {
    results.innerHTML = `<div class="error">Error: ${error.message}</div>`;
  }
}

async function refreshCVE() {
  if (!lastCve) {
    alert("Search a CVE first.");
    return;
  }

  document.getElementById("cveInput").value = lastCve;
  await searchCVE();
}

function renderResult(data) {
  const results = document.getElementById("results");

  const nvd = data.nvd || {};
  const cvss = nvd.cvss || {};
  const epss = data.epss || {};
  const kev = data.kev || {};

  const epssPercent = epss.found && epss.percentile !== undefined
    ? `${(epss.percentile * 100).toFixed(2)}%`
    : "NA";

  const epssScore = epss.found && epss.epss !== undefined
    ? epss.epss.toFixed(5)
    : "NA";

  results.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>CVE</th>
          <th>Description</th>
          <th>CVSS</th>
          <th>Severity</th>
          <th>EPSS</th>
          <th>KEV</th>
          <th>Last Modified</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td class="cve-id">${data.cve_id}</td>
          <td>${shorten(nvd.description, 150)}</td>
          <td>${cvss.available ? `${cvss.version} / ${cvss.base_score}` : "NA"}</td>
          <td><span class="badge ${severityClass(cvss.base_severity)}">${cvss.base_severity || "NA"}</span></td>
          <td>${epssScore}<br><span class="muted">${epssPercent}</span></td>
          <td>${kev.found ? `<span class="badge critical">YES</span>` : `<span class="badge low">NO</span>`}</td>
          <td>${nvd.last_modified || "NA"}</td>
          <td><button onclick="openModal()">Open</button></td>
        </tr>
      </tbody>
    </table>
  `;
}

function openModal() {
  if (!lastData) return;

  const nvd = lastData.nvd || {};
  const cvss = nvd.cvss || {};
  const epss = lastData.epss || {};
  const kev = lastData.kev || {};

  const modalContent = document.getElementById("modalContent");

  modalContent.innerHTML = `
    <h2>${lastData.cve_id}</h2>

    <h3>Summary</h3>
    <p>${nvd.description || "NA"}</p>

    <div class="grid">
      <div class="card">
        <h3>CVSS</h3>
        <p><strong>Version:</strong> ${cvss.version || "NA"}</p>
        <p><strong>Base Score:</strong> ${cvss.base_score || "NA"}</p>
        <p><strong>Severity:</strong> ${cvss.base_severity || "NA"}</p>
        <p><strong>Exploitability Score:</strong> ${cvss.exploitability_score || "NA"}</p>
        <p><strong>Impact Score:</strong> ${cvss.impact_score || "NA"}</p>
        <p><strong>Vector:</strong><br><code>${cvss.vector || "NA"}</code></p>
      </div>

      <div class="card">
        <h3>EPSS</h3>
        <p><strong>Found:</strong> ${epss.found ? "Yes" : "No"}</p>
        <p><strong>Score:</strong> ${epss.epss ?? "NA"}</p>
        <p><strong>Percentile:</strong> ${epss.percentile ?? "NA"}</p>
        <p><strong>Date:</strong> ${epss.date || "NA"}</p>
      </div>

      <div class="card">
        <h3>CISA KEV</h3>
        <p><strong>Status:</strong> ${kev.found ? "Known Exploited" : "Not listed"}</p>
        <p><strong>Vendor:</strong> ${kev.vendor_project || "NA"}</p>
        <p><strong>Product:</strong> ${kev.product || "NA"}</p>
        <p><strong>Date Added:</strong> ${kev.date_added || "NA"}</p>
        <p><strong>Due Date:</strong> ${kev.due_date || "NA"}</p>
      </div>
    </div>

    <h3>Required Action</h3>
    <p>${kev.required_action || "NA"}</p>

    <h3>References</h3>
    <ul>
      ${(nvd.references || []).slice(0, 10).map(ref => `
        <li><a href="${ref.url}" target="_blank">${ref.url}</a></li>
      `).join("")}
    </ul>
  `;

  document.getElementById("modal").classList.remove("hidden");
}

function closeModal() {
  document.getElementById("modal").classList.add("hidden");
}

function shorten(text, maxLength) {
  if (!text) return "NA";
  return text.length > maxLength ? text.slice(0, maxLength) + "..." : text;
}

function severityClass(severity) {
  if (!severity) return "unknown";

  const s = severity.toLowerCase();

  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";

  return "unknown";
}