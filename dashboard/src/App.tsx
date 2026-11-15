import { useEffect, useState } from "react";
import type { FormEvent } from "react";

type Summary = {
  repositories: number;
  scans: number;
  critical_findings: number;
  pending_reviews: number;
};

type Commit = {
  sha: string;
  short_sha: string;
  subject: string;
  author: string;
  authored_at: string;
};

type Repository = {
  name: string;
  root_path: string;
  current_branch: string;
  branches: string[];
  files: string[];
  commits: Commit[];
  symbol_count: number;
  api_endpoint_count: number;
  persisted: boolean;
};

type GitHubRepository = {
  name: string;
  url: string;
  default_branch: string;
  description: string | null;
  stars: number;
  commits: Commit[];
  pull_requests: { number: number; title: string; state: string; author?: string; url?: string }[];
  persisted: boolean;
};

type ChangedFile = {
  status: string;
  path: string;
  old_path?: string;
  new_path?: string;
  additions: number;
  deletions: number;
  hunks: { header: string; symbols: string[] }[];
};

type Comparison = {
  base_ref: string;
  target_ref: string;
  files_changed: number;
  additions: number;
  deletions: number;
  added_files: number;
  modified_files: number;
  deleted_files: number;
  renamed_files: number;
  changed_files: ChangedFile[];
  changed_functions: string[];
  api_changes: { change_type: string; method: string; path: string; details: string[]; breaking: boolean }[];
  breaking_findings: { severity: string; rule: string; method: string; path: string; details: string }[];
  openapi_files: string[];
};

type ImpactNode = {
  id: string;
  label: string;
  type: "service" | "api" | "database";
  affected: boolean;
};

type Impact = {
  nodes: ImpactNode[];
  edges: { source: string; target: string; label: string }[];
  affected_services: string[];
  affected_clients: string[];
  database_findings: { change_type: string; object_type: string; object: string; details: string; breaking: boolean }[];
};

type RetrievalResult = {
  path: string;
  source_type: string;
  content: string;
  score: number;
  bm25_score: number;
  vector_score: number;
};

type SecurityFinding = {
  analyzer: string;
  rule: string;
  severity: string;
  path: string;
  line?: number;
  message: string;
  evidence: string;
  explanation?: { category?: string; explanation?: string; recommendation?: string; provider?: string };
};

type ScanHistory = {
  scan_type: string;
  status: string;
  finding_count: number;
  critical_count: number;
  high_count: number;
  created_at: string;
};

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";
const initialSummary: Summary = {
  repositories: 0,
  scans: 0,
  critical_findings: 0,
  pending_reviews: 0,
};

function ImpactGraph({ impact }: { impact: Impact }) {
  const width = 760;
  const height = Math.max(220, Math.ceil(impact.nodes.length / 3) * 92);
  const positions = new Map(impact.nodes.map((node, index) => [
    node.id,
    { x: 130 + (index % 3) * 250, y: 48 + Math.floor(index / 3) * 92 },
  ]));
  return (
    <div className="impact-graph">
      <svg viewBox={"0 0 " + width + " " + height} role="img" aria-label="Service and API dependency graph">
        <defs>
          <marker id="impact-arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
            <path d="M0,0 L0,6 L8,3 z" fill="#6f82a8" />
          </marker>
        </defs>
        {impact.edges.map((edge, index) => {
          const source = positions.get(edge.source);
          const target = positions.get(edge.target);
          if (!source || !target) return null;
          return <line key={edge.source + edge.target + index} x1={source.x} y1={source.y} x2={target.x} y2={target.y} stroke="#51627f" strokeWidth="1.5" markerEnd="url(#impact-arrow)" />;
        })}
        {impact.nodes.map((node) => {
          const position = positions.get(node.id);
          if (!position) return null;
          return (
            <g key={node.id}>
              <rect x={position.x - 100} y={position.y - 22} width="200" height="44" rx="9" className={"graph-node graph-" + node.type + (node.affected ? " graph-affected" : "")} />
              <text x={position.x} y={position.y + 4} textAnchor="middle" className="graph-label">{node.label.length > 25 ? node.label.slice(0, 24) + "…" : node.label}</text>
            </g>
          );
        })}
      </svg>
      <div className="graph-legend">
        <span><i className="legend-swatch graph-service" /> service</span>
        <span><i className="legend-swatch graph-api" /> API</span>
        <span><i className="legend-swatch graph-database" /> database</span>
        <span><i className="legend-swatch graph-affected" /> affected</span>
      </div>
    </div>
  );
}

export function App() {
  const [summary, setSummary] = useState<Summary>(initialSummary);
  const [apiStatus, setApiStatus] = useState("Checking API...");
  const [repositoryPath, setRepositoryPath] = useState("");
  const [repository, setRepository] = useState<Repository | null>(null);
  const [repositoryError, setRepositoryError] = useState("");
  const [isInspecting, setIsInspecting] = useState(false);
  const [baseCommit, setBaseCommit] = useState("");
  const [targetCommit, setTargetCommit] = useState("");
  const [comparison, setComparison] = useState<Comparison | null>(null);
  const [comparisonError, setComparisonError] = useState("");
  const [isComparing, setIsComparing] = useState(false);
  const [impact, setImpact] = useState<Impact | null>(null);
  const [retrievalQuery, setRetrievalQuery] = useState("");
  const [retrievalResults, setRetrievalResults] = useState<RetrievalResult[]>([]);
  const [retrievalStatus, setRetrievalStatus] = useState("");
  const [findingExplanation, setFindingExplanation] = useState<Record<string, unknown> | null>(null);
  const [securityFindings, setSecurityFindings] = useState<SecurityFinding[]>([]);
  const [securityStatus, setSecurityStatus] = useState("");
  const [scanHistory, setScanHistory] = useState<ScanHistory[]>([]);
  const [benchmark, setBenchmark] = useState<Record<string, unknown> | null>(null);
  const [githubUrl, setGithubUrl] = useState("");
  const [githubRepository, setGithubRepository] = useState<GitHubRepository | null>(null);
  const [githubError, setGithubError] = useState("");
  const [isInspectingGithub, setIsInspectingGithub] = useState(false);

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

  async function inspectRepository(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setRepositoryError("");
    setIsInspecting(true);

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/repositories/inspect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ root_path: repositoryPath }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Repository inspection failed.");
      setRepository(data);
      setComparison(null);
      setImpact(null);
      setBaseCommit(data.commits.length > 1 ? data.commits[1].sha : "");
      setTargetCommit(data.commits.length > 0 ? data.commits[0].sha : "");
    } catch (error) {
      setRepositoryError(error instanceof Error ? error.message : "Repository inspection failed.");
    } finally {
      setIsInspecting(false);
    }
  }

  async function compareRepository(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setComparisonError("");
    setIsComparing(true);

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/repositories/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ root_path: repositoryPath, base_ref: baseCommit, target_ref: targetCommit }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Repository comparison failed.");
      setComparison(data);
      const impactResponse = await fetch(API_BASE_URL + "/api/v1/repositories/impact", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ root_path: repositoryPath, base_ref: baseCommit, target_ref: targetCommit }),
      });
      const impactData = await impactResponse.json();
      if (!impactResponse.ok) throw new Error(impactData.detail ?? "Dependency impact analysis failed.");
      setImpact(impactData);
    } catch (error) {
      setComparisonError(error instanceof Error ? error.message : "Repository comparison failed.");
    } finally {
      setIsComparing(false);
    }
  }

  async function inspectGithub(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setGithubError("");
    setIsInspectingGithub(true);
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/github/inspect`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repository_url: githubUrl }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "GitHub repository inspection failed.");
      setGithubRepository(data);
    } catch (error) {
      setGithubError(error instanceof Error ? error.message : "GitHub repository inspection failed.");
    } finally {
      setIsInspectingGithub(false);
    }
  }

  async function indexRepository() {
    setRetrievalStatus("Indexing repository...");
    try {
      const response = await fetch(API_BASE_URL + "/api/v1/repositories/retrieval/index", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ root_path: repositoryPath }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Indexing failed.");
      setRetrievalStatus(data.chunks_indexed + " chunks indexed");
    } catch (error) {
      setRetrievalStatus(error instanceof Error ? error.message : "Indexing failed.");
    }
  }

  async function searchRepository(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setRetrievalStatus("Searching...");
    try {
      const response = await fetch(API_BASE_URL + "/api/v1/repositories/retrieval/search", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ root_path: repositoryPath, query: retrievalQuery, top_k: 5 }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Search failed.");
      setRetrievalResults(data.results);
      setRetrievalStatus(data.results.length + " relevant chunks found");
    } catch (error) {
      setRetrievalStatus(error instanceof Error ? error.message : "Search failed.");
    }
  }

  async function explainFinding() {
    if (!retrievalQuery) return;
    setRetrievalStatus("Classifying finding...");
    const response = await fetch(API_BASE_URL + "/api/v1/repositories/retrieval/explain", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ root_path: repositoryPath, finding: retrievalQuery, top_k: 5 }),
    });
    const data = await response.json();
    if (!response.ok) {
      setRetrievalStatus(data.detail ?? "Explanation failed.");
      return;
    }
    setFindingExplanation(data);
    setRetrievalStatus("Finding classified with retrieved evidence");
  }

  async function scanSecurity() {
    setSecurityStatus("Running security analyzers...");
    try {
      const response = await fetch(API_BASE_URL + "/api/v1/repositories/security/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ root_path: repositoryPath }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail ?? "Security scan failed.");
      setSecurityFindings(data.findings);
      setSecurityStatus(data.finding_count + " findings · Bandit: " + data.analyzer_status.bandit + " · Semgrep: " + data.analyzer_status.semgrep);
      const historyResponse = await fetch(API_BASE_URL + "/api/v1/repositories/history", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ root_path: repositoryPath }),
      });
      const historyData = await historyResponse.json();
      if (historyResponse.ok) setScanHistory(historyData.history);
    } catch (error) {
      setSecurityStatus(error instanceof Error ? error.message : "Security scan failed.");
    }
  }

  async function runBenchmark() {
    const response = await fetch(API_BASE_URL + "/api/v1/evaluation/benchmark", { method: "POST" });
    const data = await response.json();
    if (response.ok) setBenchmark(data);
  }

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
        <form className="repository-form" onSubmit={inspectRepository}>
          <input
            value={repositoryPath}
            onChange={(event) => setRepositoryPath(event.target.value)}
            placeholder="/Users/you/Projects/repository"
            aria-label="Local repository path"
            required
          />
          <button type="submit" disabled={isInspecting}>
            {isInspecting ? "Inspecting..." : "Inspect repository"}
          </button>
        </form>
      </section>

      <section className="github-panel">
        <div>
          <p className="eyebrow muted">GITHUB CONNECTOR</p>
          <h2>Inspect a GitHub repository</h2>
          <p>Load repository metadata, commits, and pull requests through the GitHub API.</p>
        </div>
        <form className="github-form" onSubmit={inspectGithub}>
          <input
            value={githubUrl}
            onChange={(event) => setGithubUrl(event.target.value)}
            placeholder="https://github.com/owner/repository"
            aria-label="GitHub repository URL"
            required
          />
          <button type="submit" disabled={isInspectingGithub}>
            {isInspectingGithub ? "Loading..." : "Connect GitHub"}
          </button>
        </form>
        {githubError && <div className="error-banner">{githubError}</div>}
        {githubRepository && (
          <div className="github-result">
            <div>
              <strong>{githubRepository.name}</strong>
              <p>{githubRepository.description || "No description provided."}</p>
            </div>
            <span>{githubRepository.commits.length} commits · {githubRepository.pull_requests.length} pull requests</span>
          </div>
        )}
      </section>

      {repositoryError && <div className="error-banner">{repositoryError}</div>}

      {repository && (
        <section className="repository-panel">
          <div className="repository-heading">
            <div>
              <p className="eyebrow muted">REPOSITORY INSPECTED</p>
              <h2>{repository.name}</h2>
              <p className="path-label">{repository.root_path}</p>
            </div>
            <span className="branch-badge">⎇ {repository.current_branch}</span>
          </div>
          <div className="repository-grid">
            <div className="data-card">
              <h3>Branches</h3>
              <div className="chip-list">
                {repository.branches.map((branch) => <span className="chip" key={branch}>{branch}</span>)}
              </div>
            </div>
            <div className="data-card">
              <h3>Files</h3>
              <strong className="large-number">{repository.files.length}</strong>
              <p>tracked files detected</p>
            </div>
            <div className="data-card">
              <h3>Source symbols</h3>
              <strong className="large-number">{repository.symbol_count}</strong>
              <p>functions and classes parsed</p>
            </div>
            <div className="data-card">
              <h3>OpenAPI endpoints</h3>
              <strong className="large-number">{repository.api_endpoint_count}</strong>
              <p>operations extracted</p>
            </div>
          </div>
          <form className="compare-form" onSubmit={compareRepository}>
            <div>
              <p className="eyebrow muted">COMPARE COMMITS</p>
              <h3>Choose a base and target</h3>
            </div>
            <label>
              Base commit
              <select value={baseCommit} onChange={(event) => setBaseCommit(event.target.value)} required>
                <option value="">Select base commit</option>
                {repository.commits.map((commit) => <option value={commit.sha} key={`base-${commit.sha}`}>{commit.short_sha} — {commit.subject}</option>)}
              </select>
            </label>
            <label>
              Target commit
              <select value={targetCommit} onChange={(event) => setTargetCommit(event.target.value)} required>
                <option value="">Select target commit</option>
                {repository.commits.map((commit) => <option value={commit.sha} key={`target-${commit.sha}`}>{commit.short_sha} — {commit.subject}</option>)}
              </select>
            </label>
            <button type="submit" disabled={isComparing || repository.commits.length < 2}>
              {isComparing ? "Comparing..." : "Compare commits"}
            </button>
          </form>
          {comparisonError && <div className="error-banner">{comparisonError}</div>}
          {comparison && (
            <div className="comparison-results">
              <div className="comparison-header">
                <div>
                  <p className="eyebrow muted">CHANGE ANALYSIS</p>
                  <h3>{comparison.files_changed} files changed</h3>
                </div>
                <span className="diff-badge">+{comparison.additions} / -{comparison.deletions}</span>
              </div>
              <div className="diff-summary">
                <span><strong>{comparison.added_files}</strong> added</span>
                <span><strong>{comparison.modified_files}</strong> modified</span>
                <span><strong>{comparison.deleted_files}</strong> deleted</span>
                <span><strong>{comparison.renamed_files}</strong> renamed</span>
              </div>
              <div className={`analysis-banner ${comparison.breaking_findings.length ? "has-breaking" : "clean"}`}>
                <strong>{comparison.breaking_findings.length ? `${comparison.breaking_findings.length} breaking API finding(s)` : "No obvious breaking API changes"}</strong>
                <span>{comparison.openapi_files.length ? comparison.openapi_files.join(", ") : "No OpenAPI files found in either commit"}</span>
              </div>
              {impact && (
                <div className="impact-panel">
                  <div className="analysis-section">
                    <h4>Dependency and impact analysis</h4>
                    <div className="impact-summary">
                      <span><strong>{impact.affected_services.length}</strong> affected services</span>
                      <span><strong>{impact.affected_clients.length}</strong> affected clients</span>
                      <span><strong>{impact.database_findings.length}</strong> database findings</span>
                    </div>
                    <ImpactGraph impact={impact} />
                  </div>
                  {impact.database_findings.length > 0 && (
                    <div className="analysis-section">
                      <h4>Database-schema impact</h4>
                      {impact.database_findings.map((finding, index) => (
                        <div className="finding-row" key={finding.object + "-" + index}>
                          <span className={"severity-pill " + (finding.breaking ? "" : "severity-review")}>{finding.breaking ? "high" : "review"}</span>
                          <div><strong>{finding.change_type} {finding.object_type}: {finding.object}</strong><small>{finding.details}</small></div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
              {comparison.api_changes.length > 0 && (
                <div className="analysis-section">
                  <h4>API changes</h4>
                  {comparison.api_changes.map((change) => (
                    <div className="api-change-row" key={`${change.change_type}-${change.method}-${change.path}`}>
                      <span className={`change-pill change-${change.change_type}`}>{change.change_type}</span>
                      <strong>{change.method} {change.path}</strong>
                      <small>{change.details.join(" ")}</small>
                    </div>
                  ))}
                </div>
              )}
              {comparison.breaking_findings.length > 0 && (
                <div className="analysis-section">
                  <h4>Breaking findings</h4>
                  {comparison.breaking_findings.map((finding, index) => (
                    <div className="finding-row" key={`${finding.rule}-${finding.path}-${index}`}>
                      <span className="severity-pill">{finding.severity}</span>
                      <div><strong>{finding.method} {finding.path}</strong><small>{finding.details}</small></div>
                    </div>
                  ))}
                </div>
              )}
              {comparison.changed_functions.length > 0 && (
                <div className="analysis-section">
                  <h4>Changed functions and symbols</h4>
                  <div className="symbol-list">{comparison.changed_functions.map((symbol) => <span className="chip" key={symbol}>{symbol}</span>)}</div>
                </div>
              )}
              <div className="changed-files">
                {comparison.changed_files.map((file) => (
                  <div className="changed-file-row" key={`${file.status}-${file.path}`}>
                    <span className={`file-status status-${file.status}`}>{file.status}</span>
                    <div>
                      <strong>{file.path}</strong>
                      <small>{file.hunks.flatMap((hunk) => hunk.symbols).join(", ") || "No symbol context detected"}</small>
                    </div>
                    <span className="line-count">+{file.additions} / -{file.deletions}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          <section className="retrieval-panel">
            <div className="retrieval-heading">
              <div>
                <p className="eyebrow muted">WEEK 5 RETRIEVAL AND AI</p>
                <h3>Search engineering evidence</h3>
                <p>Retrieve relevant code, policies, documentation, and schema context before explaining a finding.</p>
              </div>
              <button type="button" className="secondary-button" onClick={indexRepository}>Build retrieval index</button>
            </div>
            <form className="retrieval-form" onSubmit={searchRepository}>
              <input value={retrievalQuery} onChange={(event) => setRetrievalQuery(event.target.value)} placeholder="e.g. database schema migration or removed API response" required />
              <button type="submit">Search</button>
              <button type="button" className="secondary-button" onClick={explainFinding} disabled={!retrievalQuery}>Classify and explain</button>
            </form>
            {retrievalStatus && <p className="retrieval-status">{retrievalStatus}</p>}
            {findingExplanation && (
              <div className="explanation-card">
                <div className="explanation-topline"><span className="change-pill change-modified">{String(findingExplanation.category ?? "finding")}</span><strong>{String(findingExplanation.severity ?? "review")}</strong></div>
                <p>{String(findingExplanation.explanation ?? "")}</p>
                <small>{String(findingExplanation.recommendation ?? "")}</small>
                <div className="evidence-list">{(Array.isArray(findingExplanation.evidence) ? findingExplanation.evidence : []).map((item, index) => <span className="chip" key={index}>{String((item as { path?: string }).path ?? "evidence")}</span>)}</div>
              </div>
            )}
            {retrievalResults.length > 0 && (
              <div className="retrieval-results">
                {retrievalResults.map((result, index) => (
                  <article className="retrieval-result" key={result.path + "-" + index}>
                    <div><strong>{result.path}</strong><span>{result.source_type} · score {result.score}</span></div>
                    <p>{result.content.slice(0, 280)}{result.content.length > 280 ? "…" : ""}</p>
                  </article>
                ))}
              </div>
            )}
          </section>
          <section className="security-panel">
            <div className="retrieval-heading">
              <div>
                <p className="eyebrow muted">WEEK 6 SECURITY ANALYSIS</p>
                <h3>Scan authentication, authorization, and credentials</h3>
                <p>Combines SecureChange checks with Bandit, Semgrep, and retrieved evidence.</p>
              </div>
              <button type="button" className="security-button" onClick={scanSecurity}>Run security scan</button>
            </div>
            {securityStatus && <p className="retrieval-status">{securityStatus}</p>}
            {securityFindings.length > 0 && (
              <div className="security-results">
                {securityFindings.map((finding, index) => (
                  <article className="security-result" key={finding.rule + finding.path + index}>
                    <div className="security-result-top">
                      <span className={"severity-pill severity-" + finding.severity}>{finding.severity}</span>
                      <strong>{finding.rule}</strong>
                      <span className="security-analyzer">{finding.analyzer}</span>
                    </div>
                    <p>{finding.message}</p>
                    <small>{finding.path}{finding.line ? ":" + finding.line : ""}</small>
                    {finding.explanation && (
                      <div className="security-explanation">
                        <strong>{finding.explanation.category ?? "security"} · {finding.explanation.provider ?? "retrieval"}</strong>
                        <span>{finding.explanation.explanation ?? ""}</span>
                        <small>{finding.explanation.recommendation ?? ""}</small>
                      </div>
                    )}
                  </article>
                ))}
              </div>
            )}
          </section>
          <section className="evaluation-panel">
            <div className="retrieval-heading">
              <div>
                <p className="eyebrow muted">WEEK 7 EVALUATION</p>
                <h3>Benchmark and scan history</h3>
                <p>Measure detection quality on intentionally seeded bugs and review previous scans.</p>
              </div>
              <button type="button" className="secondary-button" onClick={runBenchmark}>Run benchmark</button>
            </div>
            {benchmark && (
              <div className="benchmark-metrics">
                {Object.entries((benchmark.metrics ?? {}) as Record<string, unknown>).map(([key, value]) => (
                  <span key={key}><strong>{String(value)}</strong> {key.split("_").join(" ")}</span>
                ))}
              </div>
            )}
            {scanHistory.length > 0 && (
              <div className="history-list">
                {scanHistory.map((item, index) => (
                  <div className="history-row" key={item.created_at + index}>
                    <strong>{item.scan_type}</strong><span>{item.finding_count} findings · {item.high_count} high</span><small>{new Date(item.created_at).toLocaleString()}</small>
                  </div>
                ))}
              </div>
            )}
          </section>
          <div className="data-card commits-card">
            <h3>Recent commits</h3>
            {repository.commits.map((commit) => (
              <div className="commit-row" key={commit.sha}>
                <code>{commit.short_sha}</code>
                <span>{commit.subject}</span>
                <small>{commit.author}</small>
              </div>
            ))}
          </div>
        </section>
      )}

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
        <p>{repository ? "Repository files and commits are ready for change analysis." : "Enter a local Git repository path above to begin ingestion."}</p>
      </section>
    </main>
  );
}

