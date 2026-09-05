<div align="center">

# 🛡️ CloudShield — Backend

**An automated DevSecOps orchestrator.** Point it at a public GitHub repository and it clones it, runs four real security tools against it, and uses AI to draft a remediation patch for every finding — scaled to how severe and how confident each finding actually is.

[![Java](https://img.shields.io/badge/Java-17+-ED8B00?style=flat-square&logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring_Boot-6DB33F?style=flat-square&logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![Maven](https://img.shields.io/badge/Maven-C71A36?style=flat-square&logo=apachemaven&logoColor=white)](https://maven.apache.org/)

</div>

---

## What this actually does

Most "AI security scanner" projects are a thin wrapper: run one tool, paste the output into ChatGPT, done. This one is a real pipeline:

```
POST /start  →  clone repo  →  run 4 scanners  →  AI writes a fix per finding  →  save to DB
                    │
                    └── every step streams live progress back to the frontend in real time
```

1. **Clone** — pulls down the target repository into a temporary folder
2. **Scan** — runs four industry-standard tools against it, one after another:

   | Tool | What it checks |
   |---|---|
   | [gitleaks](https://github.com/gitleaks/gitleaks) | Hardcoded secrets and API keys |
   | [semgrep](https://semgrep.dev/) | Static code analysis (SAST) |
   | [trivy](https://aquasecurity.github.io/trivy/) | Vulnerable dependencies (SCA) |
   | [checkov](https://www.checkov.io/) | Misconfigured infrastructure/Dockerfiles (IaC) |

3. **Enrich** — every finding gets sent to Gemini, which writes a fix. The prompt isn't the same every time — it adapts based on severity and how confident the scanner is that the finding is real (see below)
4. **Save & clean up** — results go into a local database, and the cloned repo is deleted

## What makes this more than a script

- **It runs in the background, for real.** A scan can take a minute or two. Instead of making the frontend sit on a blocked HTTP request the whole time, `/start` returns instantly with a job ID, the actual work happens on a background thread pool, and progress streams live to the frontend over **Server-Sent Events**.
- **It knows which tool found what.** Every finding is tagged with the exact tool that produced it (`gitleaks`, `semgrep`, `trivy`, or `checkov`) — no guessing after the fact.
- **It catches its own false positives.** Before calling something a CRITICAL secret, it checks the file path (is this a test file?) and the actual entropy of the matched value (does it decode to a random key, or to something like `"some auth key"`?). A placeholder in a test fixture gets flagged as low-confidence instead of triggering a false alarm.
- **The AI doesn't panic over nothing.** A missing `HEALTHCHECK` in a Dockerfile gets two calm sentences. A real hardcoded production credential gets told to rotate the key and check git history. The prompt is explicitly told not to invent a story about why something looks safe unless the evidence actually supports it.

---

## 🧰 Requirements

You'll need these installed and available on your system `PATH` — the backend calls them directly as CLI tools:

- **Java 17+**
- **Maven** (or just use the included `./mvnw` wrapper, no separate install needed)
- [gitleaks](https://github.com/gitleaks/gitleaks#installing)
- [semgrep](https://semgrep.dev/docs/getting-started/)
- [trivy](https://aquasecurity.github.io/trivy/latest/getting-started/installation/)
- [checkov](https://www.checkov.io/2.Basics/Installing%20Checkov.html)
- A free **Gemini API key** from [Google AI Studio](https://aistudio.google.com/apikey)

## 🚀 Getting started

**1. Set your API key as an environment variable** — never put it directly in a file:

```bash
export GEMINI_API_KEY="your-key-here"
```

**2. Run it:**

```bash
./mvnw spring-boot:run
```

The server starts on `http://localhost:8080`. That's it — no database setup needed, it uses an embedded file-based H2 database that creates itself on first run.

---

## 📡 API Reference

| Method | Endpoint | What it does |
|---|---|---|
| `POST` | `/start` | Body: `{ "repoUrl": "..." }`. Kicks off a scan in the background, returns `{ "jobId": "..." }` immediately. |
| `GET` | `/scan/{jobId}/stream` | Server-Sent Events stream. Emits live `progress` events as each tool runs, then `complete` or `error`. |
| `GET` | `/scan/{jobId}` | Snapshot of a job's current status — used to fetch the final results once a scan completes. |
| `GET` | `/history` | Returns every finding ever saved. |
| `DELETE` | `/history/clear` | Deletes all saved findings. |
| `GET` | `/export/{id}` | Downloads a single finding as a JSON file. |

### Example: what a `progress` event looks like

```json
{ "status": "SCANNING", "step": "Running static analysis (SAST)", "tool": "semgrep" }
```

### Example: what a finished finding looks like

```json
{
  "id": 42,
  "ruleName": "IaC: CKV_DOCKER_3",
  "filePath": "/Dockerfile",
  "lineNumber": 12,
  "severity": "HIGH",
  "tool": "checkov",
  "aiSuggestedPatch": "..."
}
```

---

## 📁 Project structure

```
src/main/java/com/cloudshield/
├── config/
│   └── AsyncConfig.java             # Thread pool for background scans
├── controller/
│   └── ScanController.java          # REST + SSE endpoints
├── model/
│   ├── SecretFinding.java           # A single finding (saved to DB)
│   └── ScanJob.java                 # In-memory state of a running scan
├── repository/
│   └── FindingRepository.java       # DB access for findings
└── service/
    ├── GitCloneService.java         # Clones the target repo
    ├── SecretScannerService.java    # Runs the 4 tools, parses their output
    ├── ScanOrchestratorService.java # Runs the whole pipeline asynchronously
    ├── ScanProgressService.java     # Tracks job state, pushes SSE updates
    └── AIPatchService.java          # Calls Gemini, builds the fix prompt
```

---

## ⚠️ Known limitations (honest list)

This is a working, actively-developed project — not a finished production system. Things it doesn't do yet:

- **No authentication** — anyone who can reach the API can scan anything and see all history
- **No automated tests** — nothing here is unit or integration tested yet
- **Job state lives in memory** — restarting the server loses track of any scan in progress
- **No sandboxing** — cloned repos are scanned directly on the host, with no isolation

These are the next things worth tackling if you're extending this project.

---

## 📄 License

Personal/educational project. No license specified yet.
