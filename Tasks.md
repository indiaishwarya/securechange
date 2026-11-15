For a strong, portfolio-quality SecureChange project with a working dashboard, plan for approximately **140–180 hours**.

That means:

- **2 hours/day:** 10–13 weeks
- **3 hours/day:** 7–9 weeks
- **5 hours/day:** 5–7 weeks
- **Full-time:** approximately 4–5 weeks

## Time breakdown

| Work area | Estimated time |
|---|---:|
| Project setup, repository, Docker, backend, database, dashboard foundation | 8–12 hours |
| Git repository and OpenAPI ingestion | 12–18 hours |
| Code parsing with Tree-sitter | 12–18 hours |
| API and dependency graph construction | 15–22 hours |
| PostgreSQL, pgvector, and BM25 search | 12–18 hours |
| Embeddings, reranking, and retrieval pipeline | 15–22 hours |
| LLM-based change and security analysis | 15–22 hours |
| React/TypeScript dashboard | 20–30 hours |
| GitHub Actions or pull-request integration | 8–14 hours |
| Testing, benchmark dataset, and evaluation metrics | 15–22 hours |
| Documentation, deployment, demo, and resume preparation | 10–15 hours |
| **Total** | **140–180 hours** |

## Dashboard features

The dashboard should include:

- Repository and commit selection
- Upload or GitHub repository connection
- OpenAPI specification comparison
- List of detected changes
- Severity labels: critical, high, medium, low
- Breaking-change findings
- Security-risk findings
- Affected services and files
- Dependency graph visualization
- Evidence panel showing relevant code and documentation
- LLM explanation
- Suggested tests or remediation steps
- Search and filtering
- Evaluation metrics page
- Scan history and result comparison

## Recommended development schedule

### Week 1: Foundation

- Create GitHub repository
- Set up Python backend
- Set up React/TypeScript dashboard
- Add PostgreSQL and pgvector
- Add Docker Compose
- Create database schema
- Build the first backend-to-dashboard connection

### Week 2: Repository ingestion

- Connect GitHub repositories
- Read commits and pull requests
- Parse source files
- Parse OpenAPI specifications
- Store files, APIs, commits, and metadata

### Week 3: Change detection

- Compare two commits
- Detect added, removed, and modified APIs
- Identify changed functions and files
- Detect obvious breaking API changes
- Display findings in the dashboard

### Week 4: Dependency and impact analysis

- Build service and API dependency graphs
- Identify affected clients and services
- Add database-schema impact analysis
- Add graph visualization to the dashboard

### Week 5: Retrieval and AI analysis

- Generate embeddings
- Implement BM25 and vector search
- Add reranking
- Retrieve relevant code, policies, and documentation
- Use an LLM to classify and explain findings

### Week 6: Security analysis

- Add authentication and authorization checks
- Integrate Semgrep and Bandit
- Detect missing authorization, insecure endpoints, and credential issues
- Combine static-analysis results with LLM explanations

### Week 7: Evaluation and integration

- Create a benchmark with intentionally introduced bugs
- Measure precision, recall, F1, Recall@K, and false-positive rate
- Add GitHub Actions
- Add pull-request comments
- Add scan history

### Week 8: Polish and deployment

- Improve dashboard design
- Add tests and error handling
- Add monitoring
- Deploy the application
- Write architecture documentation
- Record a demo
- Convert results into resume bullets

## Scope levels

- **Basic demo:** 35–50 hours  
- **Strong portfolio project:** 90–120 hours  
- **Interview-impressive version:** 140–180 hours  
- **Research-level version with fine-tuning and extensive benchmarking:** 200+ hours  

For Aishwarya’s goals, the best target is the **140–180-hour version**. The dashboard itself will take approximately **20–30 hours**, but it substantially improves the project because recruiters can visually see the system’s analysis, evidence, dependency graph, and evaluation results.