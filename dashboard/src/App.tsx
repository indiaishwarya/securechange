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
  const [repositoryPath, setRepositoryPath] = useState("");
  const [repository, setRepository] = useState<Repository | null>(null);
  const [repositoryError, setRepositoryError] = useState("");
  const [isInspecting, setIsInspecting] = useState(false);
  const [baseCommit, setBaseCommit] = useState("");
  const [targetCommit, setTargetCommit] = useState("");
  const [comparison, setComparison] = useState<Comparison | null>(null);
  const [comparisonError, setComparisonError] = useState("");
  const [isComparing, setIsComparing] = useState(false);
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

