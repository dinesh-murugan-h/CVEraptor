import { useEffect, useState } from "react";
import "./App.css";

const API_BASE = "http://127.0.0.1:8000";

function App() {
  const [cveInput, setCveInput] = useState("");
  const [lastCve, setLastCve] = useState("");
  const [selectedCve, setSelectedCve] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [items, setItems] = useState([]);

  useEffect(() => {
    loadLatestCves();
  }, []);

  async function loadLatestCves() {
    setLoading(true);
    setError("");
    setLastCve("");

    try {
      const response = await fetch(`${API_BASE}/api/cves/latest?days=7&limit=20`);

      if (!response.ok) {
        throw new Error(`Backend returned HTTP ${response.status}`);
      }

      const result = await response.json();

      if (result.error) {
        setError(result.error);
      }

      setItems(result.items || []);
    } catch (err) {
      setError(err.message);
      setItems([]);
    } finally {
      setLoading(false);
    }
  }

  async function searchCve(cveOverride = null) {
    const cveId = (cveOverride || cveInput).trim().toUpperCase();

    if (!cveId) {
      setError("Enter a CVE ID.");
      return;
    }

    setLoading(true);
    setError("");
    setLastCve(cveId);

    try {
      const response = await fetch(`${API_BASE}/api/cve/${cveId}`);

      if (!response.ok) {
        throw new Error(`Backend returned HTTP ${response.status}`);
      }

      const result = await response.json();
      setItems([result]);
    } catch (err) {
      setError(err.message);
      setItems([]);
    } finally {
      setLoading(false);
    }
  }

  async function refreshCurrentView() {
    if (lastCve) {
      await searchCve(lastCve);
      return;
    }

    await loadLatestCves();
  }

  return (
    <main className="page">
      <section className="hero">
        <div className="brandPill">CVE Intelligence Dashboard</div>
        <h1>cveraptor</h1>
        <p>
          Search CVEs and enrich them with NVD CVSS, FIRST EPSS, and CISA KEV intelligence.
        </p>

        <div className="searchBox">
          <input
            value={cveInput}
            onChange={(e) => setCveInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") searchCve();
            }}
            placeholder="Search CVE, e.g. CVE-2021-44228"
          />

          <button onClick={() => searchCve()}>Search</button>
          <button className="secondary" onClick={refreshCurrentView}>
            Refresh
          </button>
          <button className="secondary" onClick={loadLatestCves}>
            Latest
          </button>
        </div>

        <div className="hint">
          Try:{" "}
          <button
            className="linkBtn"
            onClick={() => {
              setCveInput("CVE-2021-44228");
              searchCve("CVE-2021-44228");
            }}
          >
            CVE-2021-44228
          </button>
        </div>
      </section>

      {loading && <div className="notice">Loading vulnerability intelligence...</div>}
      {error && <div className="error">{error}</div>}

      {items.length > 0 && (
        <CveTable
          items={items}
          onOpen={(item) => setSelectedCve(item)}
        />
      )}

      {!items.length && !loading && !error && (
        <section className="emptyState">
          <h2>No CVEs loaded</h2>
          <p>
            Click Latest to load recently published CVEs, or search for a specific CVE ID.
          </p>
        </section>
      )}

      {selectedCve && (
        <CveModal
          data={selectedCve}
          onClose={() => setSelectedCve(null)}
        />
      )}
    </main>
  );
}

function CveTable({ items, onOpen }) {
  const criticalCount = items.filter((item) => {
    const severity = item?.nvd?.cvss?.base_severity || "";
    return severity.toLowerCase() === "critical";
  }).length;

  const kevCount = items.filter((item) => item?.kev?.found).length;

  const highestCvss = items.reduce((max, item) => {
    const score = Number(item?.nvd?.cvss?.base_score);
    return Number.isFinite(score) && score > max ? score : max;
  }, 0);

  return (
    <section className="dashboard">
      <div className="summaryCards">
        <InfoCard title="Loaded CVEs" value={items.length} sub="Current result set" />
        <InfoCard title="Highest CVSS" value={highestCvss || "NA"} sub="Max base score" />
        <InfoCard title="Critical / KEV" value={`${criticalCount} / ${kevCount}`} sub="Critical severity / known exploited" danger={kevCount > 0} />
      </div>

      <div className="tableWrap">
        <table>
          <thead>
            <tr>
              <th>CVE</th>
              <th>Description</th>
              <th>CVSS</th>
              <th>Severity</th>
              <th>EPSS</th>
              <th>KEV</th>
              <th>Published</th>
              <th>Last Modified</th>
              <th>Details</th>
            </tr>
          </thead>

          <tbody>
            {items.map((item) => {
              const nvd = item.nvd || {};
              const cvss = nvd.cvss || {};
              const epss = item.epss || {};
              const kev = item.kev || {};

              const epssScore = epss.found && epss.epss !== undefined
                ? Number(epss.epss).toFixed(5)
                : "NA";

              const epssPercentile = epss.found && epss.percentile !== undefined
                ? `${(Number(epss.percentile) * 100).toFixed(2)}%`
                : "NA";

              return (
                <tr key={item.cve_id}>
                  <td className="cveId">{item.cve_id}</td>
                  <td>{shorten(nvd.description, 170)}</td>
                  <td>
                    {cvss.available
                      ? `${cvss.version} / ${cvss.base_score}`
                      : "NA"}
                  </td>
                  <td>
                    <span className={`badge ${severityClass(cvss.base_severity)}`}>
                      {cvss.base_severity || "NA"}
                    </span>
                  </td>
                  <td>
                    {epssScore}
                    <br />
                    <span className="muted">{epssPercentile}</span>
                  </td>
                  <td>
                    {kev.found ? (
                      <span className="badge critical">YES</span>
                    ) : (
                      <span className="badge low">NO</span>
                    )}
                  </td>
                  <td>{formatDate(nvd.published)}</td>
                  <td>{formatDate(nvd.last_modified)}</td>
                  <td>
                    <button onClick={() => onOpen(item)}>Open</button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function InfoCard({ title, value, sub, danger = false }) {
  return (
    <div className={`infoCard ${danger ? "dangerCard" : ""}`}>
      <p>{title}</p>
      <h2>{value}</h2>
      <span>{sub}</span>
    </div>
  );
}

function CveModal({ data, onClose }) {
  const nvd = data.nvd || {};
  const cvss = nvd.cvss || {};
  const epss = data.epss || {};
  const kev = data.kev || {};

  return (
    <div className="modalBackdrop" onClick={onClose}>
      <div className="modalCard" onClick={(e) => e.stopPropagation()}>
        <button className="closeBtn" onClick={onClose}>×</button>

        <div className="modalHeader">
          <div>
            <h2>{data.cve_id}</h2>
            <p>{nvd.status || "Unknown status"}</p>
          </div>

          <span className={`badge ${severityClass(cvss.base_severity)}`}>
            {cvss.base_severity || "NA"}
          </span>
        </div>

        <h3>Summary</h3>
        <p className="description">{nvd.description || "NA"}</p>

        <div className="grid">
          <div className="card">
            <h3>CVSS</h3>
            <p><span>Version:</span> {cvss.version || "NA"}</p>
            <p><span>Base Score:</span> {cvss.base_score ?? "NA"}</p>
            <p><span>Severity:</span> {cvss.base_severity || "NA"}</p>
            <p><span>Exploitability Score:</span> {cvss.exploitability_score ?? "NA"}</p>
            <p><span>Impact Score:</span> {cvss.impact_score ?? "NA"}</p>
            <p><span>Source:</span> {cvss.source || "NA"}</p>
            <p><span>Vector:</span></p>
            <code>{cvss.vector || "NA"}</code>
          </div>

          <div className="card">
            <h3>EPSS</h3>
            <p><span>Found:</span> {epss.found ? "Yes" : "No"}</p>
            <p><span>Score:</span> {epss.epss ?? "NA"}</p>
            <p><span>Percentile:</span> {epss.percentile ?? "NA"}</p>
            <p><span>Date:</span> {epss.date || "NA"}</p>
          </div>

          <div className="card">
            <h3>CISA KEV</h3>
            <p><span>Status:</span> {kev.found ? "Known Exploited" : "Not listed"}</p>
            <p><span>Vendor:</span> {kev.vendor_project || "NA"}</p>
            <p><span>Product:</span> {kev.product || "NA"}</p>
            <p><span>Vulnerability:</span> {kev.vulnerability_name || "NA"}</p>
            <p><span>Date Added:</span> {kev.date_added || "NA"}</p>
            <p><span>Due Date:</span> {kev.due_date || "NA"}</p>
          </div>
        </div>

        <h3>Required Action</h3>
        <p className="description">{kev.required_action || "NA"}</p>

        <h3>References</h3>
        <ul className="references">
          {(nvd.references || []).slice(0, 12).map((ref, index) => (
            <li key={index}>
              <a href={ref.url} target="_blank" rel="noreferrer">
                {ref.url}
              </a>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function shorten(text, maxLength) {
  if (!text) return "NA";
  return text.length > maxLength ? `${text.slice(0, maxLength)}...` : text;
}

function formatDate(value) {
  if (!value) return "NA";
  return value.replace("T", " ").slice(0, 19);
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

export default App;