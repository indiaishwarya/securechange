import { useEffect, useState } from "react";

type Summary = {
  repositories: number;
  scans: number;
  critical_findings: number;
  pending_reviews: number;
};

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";
const initialSummary: Summary = {
  repositories: 0,
  scans: 0,
  critical_findings: 0,
  pending_reviews: 0,
};

export function App() {
  const [summary, setSummary] = useState<Summary>(initialSummary);
  const [apiStatus, setApiStatus] = useState("Checking API...");

  useEffect(() => {
    Promise.all([
      fetch(`${API_BASE_URL}/health`).then((response) => response.json()),
      fetch(`${API_BASE_URL}/api/v1/summary`).then((response) => response.json()),
    ])
      .then(([health, dashboardSummary]) => {
        setApiStatus(health.status === "ok" ? "API connected" : "API unavailable");
        setSummary(dashboardSummary);
      })
      .catch(() => setApiStatus("API unavailable"));
  }, []);

  const cards = [
    ["Repositories", summary.repositories],
    ["Scans completed", summary.scans],
    ["Critical findings", summary.critical_findings],
    ["Pending reviews", summary.pending_reviews],
  ] as const;

  return (
    <main className="page-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">SECURECHANGE</p>
          <h1>Change impact intelligence</h1>
          <p className="subtitle">Detect breaking API changes and security risks before deployment.</p>
        </div>
        <div className="connection-pill">
          <span className={`status-dot ${apiStatus === "API connected" ? "online" : ""}`} />
          {apiStatus}
        </div>
      </header>

      <section className="hero-panel">
        <div>
          <p className="eyebrow muted">WEEK 1 FOUNDATION</p>
          <h2>Your engineering risk overview</h2>
          <p>Connect a repository to begin analyzing commits, API contracts, dependencies, and security policies.</p>
        </div>
        <button type="button">Connect repository</button>
      </section>

      <section className="metrics-grid" aria-label="Summary metrics">
        {cards.map(([label, value]) => (
          <article className="metric-card" key={label}>
            <p>{label}</p>
            <strong>{value}</strong>
          </article>
        ))}
      </section>

      <section className="empty-state">
        <div className="empty-icon">⌁</div>
        <h2>No scans yet</h2>
        <p>Repository ingestion and change analysis will appear here in Week 2.</p>
      </section>
    </main>
  );
}

