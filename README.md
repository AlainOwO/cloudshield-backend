# CloudShield Backend

A DevSecOps orchestrator that scans a public GitHub repository with multiple security tools (secret detection, SAST, SCA, and IaC scanning) and uses an AI model to generate remediation advice for each finding.

## What it does

Given a repo URL, CloudShield:
1. Clones the repository into a temporary directory
2. Runs four scanners against it:
   - **gitleaks** — hardcoded secrets
   - **semgrep** — static analysis (SAST)
   - **trivy** — dependency vulnerabilities (SCA)
   - **checkov** — infrastructure-as-code / Dockerfile misconfigurations
3. Sends each finding to Gemini to generate a tailored fix, scaled to how severe and how confident the finding actually is
4. Saves everything to a local database and deletes the cloned repo

## Requirements

- Java 17+
- Maven (or use the included `./mvnw` wrapper)
- These CLI tools installed and available on your `PATH`, since the backend shells out to them directly:
  - [gitleaks](https://github.com/gitleaks/gitleaks)
  - [semgrep](https://semgrep.dev/docs/getting-started/)
  - [trivy](https://aquasecurity.github.io/trivy/latest/getting-started/installation/)
  - [checkov](https://www.checkov.io/2.Basics/Installing%20Checkov.html)
- A Gemini API key from [Google AI Studio](https://aistudio.google.com/apikey)

## Setup

Set your Gemini API key as an environment variable — never hardcode it in the source:

```bash
export GEMINI_API_KEY="your-key-here"
```

`src/main/resources/application.properties` reads it via:
```properties
gemini.api.key=${GEMINI_API_KEY}
```

## Run

```bash
./mvnw spring-boot:run
```

The server starts on `http://localhost:8080`.

## API

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/start` | Body: `{ "repoUrl": "..." }`. Clones, scans, and returns findings with AI-suggested patches. |
| `GET` | `/history` | Returns all past findings stored in the database. |
| `DELETE` | `/history/clear` | Deletes all stored findings. |
| `GET` | `/export/{id}` | Downloads a single finding as JSON. |

## Notes

- Findings are stored in a local H2 database file (`cloudshield-data.mv.db`), which is gitignored and should never be committed — it may contain data from scanned repositories.
- Review every AI-suggested patch before applying it; it's a starting point, not an automatic fix.
