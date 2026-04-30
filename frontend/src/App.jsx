import { useEffect, useState } from "react";
import "./App.css";

const API_BASE = "http://127.0.0.1:8000";

const DEFAULT_FILTERS = {
  kev: "all",
  exploitation: "all",
  automatable: "all",
  technicalImpact: "all",
};

function App() {
  const [cveInput, setCveInput] = useState("");
  const [searchMode, setSearchMode] = useState(false);
  const [selectedCve, setSelectedCve] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const [items, setItems] = useState([]);
  const [page, setPage] = useState(1);
  const [resultsPerPage, setResultsPerPage] = useState(25);
  const [totalResults, setTotalResults] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [scanInfo, setScanInfo] = useState(null);
  const [filters, setFilters] = useState(DEFAULT_FILTERS);

  useEffect(() => {
    loadCves(1, resultsPerPage, "", DEFAULT_FILTERS);
  }, []);

  async function loadCves(
    nextPage = page,
    nextResultsPerPage = resultsPerPage,
    nextKeyword = cveInput,
    nextFilters = filters
  ) {
    setLoading(true);
    setError("");
    setSearchMode(false);

    try {
      const params = new URLSearchParams();

      params.set("results_per_page", String(nextResultsPerPage));
      params.set("page", String(nextPage));
      params.set("max_scan_pages", "6");

      const keyword = nextKeyword.trim();

      if (keyword) {
        params.set("keyword", keyword);
      }

      params.set("kev", nextFilters.kev);
      params.set("exploitation", nextFilters.exploitation);
      params.set("automatable", nextFilters.automatable);
      params.set("technical_impact", nextFilters.technicalImpact);

      const response = await fetch(`${API_BASE}/api/cves?${params.toString()}`);

      if (!response.ok) {
        throw new Error(`Backend returned HTTP ${response.status}`);
      }

      const result = await response.json();

      if (result.error) {
        setError(result.error);
      }

      setItems(result.items || []);
      setPage(result.page || nextPage);
      setResultsPerPage(result.results_per_page || nextResultsPerPage);
      setTotalResults(result.total_results || 0);
      setTotalPages(result.total_pages || 0);
      setScanInfo(result.scan || null);
    } catch (err) {
      setError(err.message);
      setItems([]);
      setScanInfo(null);
    } finally {
      setLoading(false);
    }
  }

  async function searchCveById(cveIdRaw) {
    const cveId = cveIdRaw.trim().toUpperCase();

    if (!cveId) {
      setError("Enter a CVE ID.");
      return;
    }

    setLoading(true);
    setError("");
    setSearchMode(true);
    setScanInfo(null);

    try {
      const response = await fetch(`${API_BASE}/api/cve/${cveId}`);

      if (!response.ok) {
        throw new Error(`Backend returned HTTP ${response.status}`);
      }

      const result = await response.json();

      setItems([result]);
      setPage(1);
      setTotalPages(1);
      setTotalResults(1);
    } catch (err) {
      setError(err.message);
      setItems([]);
    } finally {
      setLoading(false);
    }
  }

  async function runSearch() {
    const input = cveInput.trim();

    if (!input) {
      await loadCves(1, resultsPerPage, "", filters);
      return;
    }

    if (isCveId(input) && !hasActiveFilters(filters)) {
      await searchCveById(input);
      return;
    }

    await loadCves(1, resultsPerPage, input, filters);
  }

  function refresh() {
    const input = cveInput.trim();

    if (searchMode && isCveId(input) && !hasActiveFilters(filters)) {
      searchCveById(input);
      return;
    }

    loadCves(page, resultsPerPage, cveInput, filters);
  }

  function goFirst() {
    if (page > 1) loadCves(1, resultsPerPage, cveInput, filters);
  }

  function goPrevious() {
    if (page > 1) loadCves(page - 1, resultsPerPage, cveInput, filters);
  }

  function goNext() {
    if (page < totalPages) loadCves(page + 1, resultsPerPage, cveInput, filters);
  }

  function goLast() {
    if (totalPages > 0 && page < totalPages) {
      loadCves(totalPages, resultsPerPage, cveInput, filters);
    }
  }

  function handleResultsPerPageChange(event) {
    const value = Number(event.target.value);
    loadCves(1, value, cveInput, filters);
  }

  function handleFilterChange(name, value) {
    setFilters((current) => ({
      ...current,
      [name]: value,
    }));
  }

  function applyFilters() {
    loadCves(1, resultsPerPage, cveInput, filters);
  }

  function resetFilters() {
    setFilters(DEFAULT_FILTERS);
    loadCves(1, resultsPerPage, cveInput, DEFAULT_FILTERS);
  }

  function clearSearchAndFilters() {
    setCveInput("");
    setFilters(DEFAULT_FILTERS);
    loadCves(1, resultsPerPage, "", DEFAULT_FILTERS);
  }

  const startItem = totalResults === 0 ? 0 : (page - 1) * resultsPerPage + 1;
  const endItem = Math.min(page * resultsPerPage, totalResults);

  return (
    <main className="page">
      <section className="hero">
        <div className="brandPill">CVE Intelligence Dashboard</div>
        <h1>cveraptor</h1>
        <p>
          Search CVEs or vendor/product names, then filter by CISA KEV and
          CISA Vulnrichment SSVC decision points.
        </p>

        <div className="searchBox">
          <input
            value={cveInput}
            onChange={(e) => setCveInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") runSearch();
            }}
            placeholder="Search CVE ID or vendor, e.g. Siemens, Microsoft, CVE-2023-45727"
          />

          <button onClick={runSearch}>Search</button>
          <button className="secondary" onClick={refresh}>Refresh</button>
          <button className="secondary" onClick={clearSearchAndFilters}>
            Latest
          </button>
        </div>

        <div className="hint">
          Vendor search works best before SSVC filtering. Try:{" "}
          <button
            className="linkBtn"
            onClick={() => {
              setCveInput("Microsoft");
              loadCves(1, resultsPerPage, "Microsoft", filters);
            }}
          >
            Microsoft
          </button>
          {" or "}
          <button
            className="linkBtn"
            onClick={() => {
              setCveInput("Siemens");
              loadCves(1, resultsPerPage, "Siemens", filters);
            }}
          >
            Siemens
          </button>
        </div>
      </section>

      <FilterPanel
        filters={filters}
        onChange={handleFilterChange}
        onApply={applyFilters}
        onReset={resetFilters}
      />

      {!searchMode && (
        <section className="paginationBar">
          <div className="paginationLeft">
            <label>Items per page:</label>
            <select value={resultsPerPage} onChange={handleResultsPerPageChange}>
              <option value={10}>10</option>
              <option value={25}>25</option>
              <option value={50}>50</option>
              <option value={100}>100</option>
            </select>

            <span>
              {startItem}–{endItem} of {totalResults}
              {scanInfo?.filtered_total_is_partial ? " scanned matches" : ""}
            </span>
          </div>

          <div className="paginationButtons">
            <button className="secondary" onClick={goFirst} disabled={page <= 1}>
              ⏮
            </button>
            <button className="secondary" onClick={goPrevious} disabled={page <= 1}>
              ‹
            </button>
            <span className="pageIndicator">
              Page {page} of {totalPages || 1}
            </span>
            <button className="secondary" onClick={goNext} disabled={page >= totalPages}>
              ›
            </button>
            <button className="secondary" onClick={goLast} disabled={page >= totalPages}>
              ⏭
            </button>
          </div>
        </section>
      )}

      {scanInfo?.active && (
        <section className="scanNote">
          <span>
            Filter scan: checked {scanInfo.candidates_scanned} CVEs across{" "}
            {scanInfo.pages_scanned} NVD page(s).
          </span>
          {scanInfo.filtered_total_is_partial && (
            <span>
              Results may be partial because KEV/SSVC filtering requires enrichment after
              vendor search.
            </span>
          )}
        </section>
      )}

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
            Click Latest to load CVEs, or search for a specific CVE/vendor.
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

function FilterPanel({ filters, onChange, onApply, onReset }) {
  return (
    <section className="filterPanel">
      <div className="filterHeader">
        <div>
          <h2>Filters</h2>
          <p>Use dropdowns for KEV and SSVC decision-point filtering.</p>
        </div>

        <div className="filterActions">
          <button onClick={onApply}>Apply Filters</button>
          <button className="secondary" onClick={onReset}>Reset</button>
        </div>
      </div>

      <div className="filterGrid">
        <label className="filterControl">
          <span>KEV</span>
          <select
            value={filters.kev}
            onChange={(e) => onChange("kev", e.target.value)}
          >
            <option value="all">All</option>
            <option value="yes">KEV only</option>
            <option value="no">Not KEV</option>
          </select>
        </label>

        <label className="filterControl">
          <span>SSVC Exploitation</span>
          <select
            value={filters.exploitation}
            onChange={(e) => onChange("exploitation", e.target.value)}
          >
            <option value="all">All</option>
            <option value="none">None</option>
            <option value="poc">Public PoC</option>
            <option value="active">Active</option>
            <option value="no_ssvc">No SSVC</option>
          </select>
        </label>

        <label className="filterControl">
          <span>SSVC Automatable</span>
          <select
            value={filters.automatable}
            onChange={(e) => onChange("automatable", e.target.value)}
          >
            <option value="all">All</option>
            <option value="yes">Yes</option>
            <option value="no">No</option>
            <option value="no_ssvc">No SSVC</option>
          </select>
        </label>

        <label className="filterControl">
          <span>SSVC Technical Impact</span>
          <select
            value={filters.technicalImpact}
            onChange={(e) => onChange("technicalImpact", e.target.value)}
          >
            <option value="all">All</option>
            <option value="partial">Partial</option>
            <option value="total">Total</option>
            <option value="no_ssvc">No SSVC</option>
          </select>
        </label>
      </div>
    </section>
  );
}

function CveTable({ items, onOpen }) {
  return (
    <section className="dashboard">
      <div className="tableWrap">
        <table>
          <thead>
            <tr>
              <th>CVE</th>
              <th>Vendor / Product</th>
              <th>CWE</th>
              <th>Description</th>
              <th>CVSS</th>
              <th>Severity</th>
              <th>EPSS</th>
              <th>KEV</th>
              <th>SSVC</th>
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
              const vulnrichment = item.vulnrichment || {};
              const ssvc = vulnrichment.ssvc || {};
              const affected = vulnrichment.affected || {};

              return (
                <tr key={item.cve_id}>
                  <td className="cveId">{item.cve_id}</td>

                  <td>
                    <VendorProduct
                      affected={affected}
                      kev={kev}
                    />
                  </td>

                  <td>
                    <CweList weaknesses={nvd.weaknesses || []} />
                  </td>

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
                    {formatEpss(epss.epss)}
                    <br />
                    <span className="muted">{formatPercent(epss.percentile)}</span>
                  </td>
                  <td>
                    {kev.found ? (
                      <span className="badge critical">YES</span>
                    ) : (
                      <span className="badge low">NO</span>
                    )}
                  </td>
                  <td>
                    <SsvcMini ssvc={ssvc} />
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

function VendorProduct({ affected, kev }) {
  const vendors = affected?.vendors || [];
  const products = affected?.products || [];

  const vendorText =
    vendors.length > 0
      ? vendors.slice(0, 2).join(", ")
      : kev?.vendor_project || "NA";

  const productText =
    products.length > 0
      ? products.slice(0, 2).join(", ")
      : kev?.product || "NA";

  const extraVendorCount = Math.max(vendors.length - 2, 0);
  const extraProductCount = Math.max(products.length - 2, 0);

  return (
    <div className="vendorProduct">
      <div className="vendorName">{vendorText}</div>
      <div className="muted">
        {productText}
        {extraVendorCount > 0 || extraProductCount > 0
          ? ` +${extraVendorCount + extraProductCount} more`
          : ""}
      </div>
    </div>
  );
}

function CweList({ weaknesses }) {
  const cwes = extractCwes(weaknesses);

  if (!cwes.length) {
    return <span className="badge unknown">NA</span>;
  }

  return (
    <div className="cweStack">
      {cwes.slice(0, 3).map((cwe) => (
        <span key={cwe} className="badge unknown">
          {cwe}
        </span>
      ))}
      {cwes.length > 3 && (
        <span className="muted">+{cwes.length - 3} more</span>
      )}
    </div>
  );
}

function SsvcMini({ ssvc }) {
  if (!ssvc || !ssvc.found) {
    return <span className="badge unknown">No SSVC</span>;
  }

  return (
    <div className="ssvcStack">
      <span>
        Exploit:{" "}
        <span className={`badge ${ssvcClass("exploitation", ssvc.exploitation)}`}>
          {ssvc.exploitation || "NA"}
        </span>
      </span>

      <span>
        Auto:{" "}
        <span className={`badge ${ssvcClass("automatable", ssvc.automatable)}`}>
          {ssvc.automatable || "NA"}
        </span>
      </span>

      <span>
        Impact:{" "}
        <span className={`badge ${ssvcClass("technical_impact", ssvc.technical_impact)}`}>
          {ssvc.technical_impact || "NA"}
        </span>
      </span>
    </div>
  );
}

function CveModal({ data, onClose }) {
  const nvd = data.nvd || {};
  const cvss = nvd.cvss || {};
  const epss = data.epss || {};
  const kev = data.kev || {};
  const vulnrichment = data.vulnrichment || {};
  const ssvc = vulnrichment.ssvc || {};
  const cisaCvss = vulnrichment.cisa_cvss || {};
  const kevAdp = vulnrichment.kev_adp || {};
  const provider = vulnrichment.provider || {};
  const affected = vulnrichment.affected || {};

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
            <h3>Vendor / Product</h3>
            <p><span>Vendors:</span> {(affected.vendors || []).join(", ") || kev.vendor_project || "NA"}</p>
            <p><span>Products:</span> {(affected.products || []).join(", ") || kev.product || "NA"}</p>
            <p><span>CWE:</span> {extractCwes(nvd.weaknesses || []).join(", ") || "NA"}</p>
          </div>

          <div className="card">
            <h3>NVD CVSS</h3>
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
        </div>

        <div className="grid">
          <div className="card">
            <h3>CISA KEV</h3>
            <p><span>Status:</span> {kev.found ? "Known Exploited" : "Not listed"}</p>
            <p><span>Vendor:</span> {kev.vendor_project || "NA"}</p>
            <p><span>Product:</span> {kev.product || "NA"}</p>
            <p><span>Vulnerability:</span> {kev.vulnerability_name || "NA"}</p>
            <p><span>Date Added:</span> {kev.date_added || "NA"}</p>
            <p><span>Due Date:</span> {kev.due_date || "NA"}</p>
          </div>

          <div className="card">
            <h3>CISA Vulnrichment</h3>
            <p><span>Found:</span> {vulnrichment.found ? "Yes" : "No"}</p>
            <p><span>Record Source:</span> {vulnrichment.record_source || "NA"}</p>
            <p><span>Container:</span> {vulnrichment.title || "NA"}</p>
            <p><span>Provider:</span> {provider.short_name || "NA"}</p>
            <p><span>Updated:</span> {formatDate(provider.date_updated)}</p>
          </div>

          <div className="card">
            <h3>SSVC Decision Points</h3>

            {ssvc.found ? (
              <>
                <p>
                  <span>Exploitation:</span>{" "}
                  <span className={`badge ${ssvcClass("exploitation", ssvc.exploitation)}`}>
                    {ssvc.exploitation || "NA"}
                  </span>
                </p>

                <p>
                  <span>Automatable:</span>{" "}
                  <span className={`badge ${ssvcClass("automatable", ssvc.automatable)}`}>
                    {ssvc.automatable || "NA"}
                  </span>
                </p>

                <p>
                  <span>Technical Impact:</span>{" "}
                  <span className={`badge ${ssvcClass("technical_impact", ssvc.technical_impact)}`}>
                    {ssvc.technical_impact || "NA"}
                  </span>
                </p>

                <p><span>SSVC Version:</span> {ssvc.version || "NA"}</p>
                <p><span>Role:</span> {ssvc.role || "NA"}</p>
                <p><span>Timestamp:</span> {formatDate(ssvc.timestamp)}</p>
              </>
            ) : (
              <p className="description">
                {ssvc.message || "No SSVC data found for this CVE."}
              </p>
            )}
          </div>
        </div>

        <div className="grid">
          <div className="card">
            <h3>CISA ADP Extras</h3>
            <p><span>ADP KEV:</span> {kevAdp.found ? "Yes" : "No"}</p>
            <p><span>ADP KEV Date:</span> {kevAdp.date_added || "NA"}</p>
            <p><span>CISA CVSS Found:</span> {cisaCvss.found ? "Yes" : "No"}</p>
            <p><span>CISA CVSS Score:</span> {cisaCvss.base_score ?? "NA"}</p>
            <p><span>CISA CVSS Severity:</span> {cisaCvss.base_severity || "NA"}</p>
            <p><span>CISA CVSS Vector:</span></p>
            <code>{cisaCvss.vector || "NA"}</code>
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

function formatEpss(value) {
  if (value === undefined || value === null) return "NA";
  return Number(value).toFixed(5);
}

function formatPercent(value) {
  if (value === undefined || value === null) return "NA";
  return `${(Number(value) * 100).toFixed(2)}%`;
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

function ssvcClass(field, value) {
  if (!value) return "unknown";

  const v = String(value).toLowerCase();

  if (field === "exploitation") {
    if (v === "active") return "critical";
    if (v === "poc") return "high";
    if (v === "none") return "low";
  }

  if (field === "automatable") {
    if (v === "yes") return "high";
    if (v === "no") return "low";
  }

  if (field === "technical_impact") {
    if (v === "total") return "critical";
    if (v === "partial") return "medium";
  }

  return "unknown";
}

function extractCwes(weaknesses) {
  if (!Array.isArray(weaknesses)) return [];

  const cwes = new Set();

  for (const weakness of weaknesses) {
    const descriptions = weakness.description || [];

    for (const description of descriptions) {
      const value = description.value;

      if (!value) continue;

      const matches = String(value).match(/CWE-\d+/g);

      if (matches) {
        for (const match of matches) {
          cwes.add(match);
        }
      }
    }
  }

  return Array.from(cwes);
}

function isCveId(value) {
  return /^CVE-\d{4}-\d{4,}$/i.test(value.trim());
}

function hasActiveFilters(currentFilters) {
  return (
    currentFilters.kev !== "all" ||
    currentFilters.exploitation !== "all" ||
    currentFilters.automatable !== "all" ||
    currentFilters.technicalImpact !== "all"
  );
}

export default App;