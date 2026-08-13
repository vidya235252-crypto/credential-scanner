# RepoSentinel

A security-focused web application that scans GitHub repositories for potentially exposed credentials and sensitive information — with explainable confidence scoring, remediation guidance, and per-user scan history.

**Live demo:** [credential-scanner.onrender.com/welcome](https://credential-scanner.onrender.com/welcome)

I built this project to understand how secret scanning works and to get practical experience with cybersecurity, APIs, backend development, authentication, and GitHub repository analysis.

## What it does

The scanner checks files in a GitHub repository for possible credentials, assigns a risk score, and explains *why* each finding was flagged and *what to do about it* — rather than just listing raw matches.

The main detection and analysis methods used are:

* Pattern-based detection for known credential formats
* Entropy-based detection for suspicious random-looking strings
* Explainable confidence scoring per finding
* Type-specific remediation recommendations
* Risk scoring based on the type of finding
* Repository security hygiene checks
* Commit-level attribution for detected findings
* Per-user authentication and scoped scan history

## Main Features

### Credential Detection

The scanner looks for different types of credentials and sensitive information, including:

* AWS access keys and secret keys
* Generic API keys
* Slack tokens
* Private keys
* High-entropy strings that don't match any known pattern

### Entropy Detection

Not every secret follows a known pattern. The scanner also checks for high-entropy strings that could potentially be secrets, catching suspicious values that predictable pattern-matching alone would miss.

### Confidence Scoring

Every finding gets a confidence score (0–100) built from four signals: whether it matched a known credential format, its entropy, whether it's sitting in a test/example file, and whether it looks like a known placeholder value (e.g. `example_api_key`, `changeme`). Each score comes with the specific reasons behind it, visible on hover — so a finding isn't just a number, it's an explanation.

This is distinct from severity: severity says *how bad it would be if real*, confidence says *how likely it is to actually be real*. A private key is always HIGH severity regardless of confidence, but a Slack token that's clearly a fake placeholder will still score low confidence even though it matched the token format.

### Remediation Recommendations

Every finding includes specific, actionable next steps based on its type — rotate the credential, revoke it, move it to a secrets manager, remove it from repository history. Recommendations are looked up by finding type, with a sensible generic fallback for any type not yet covered.

### Risk Scoring

Different findings have different levels of importance. A private key is treated as more serious than a generic high-entropy string. The project assigns weighted scores to different finding types and combines them into an overall repository risk score, capped at 100.

### Secret Density

Findings are also expressed relative to repository size (findings per 100 files scanned), making it possible to compare repositories of different sizes on a fairer basis than raw finding counts alone.

### Commit Attribution

When a potential credential is found, the scanner identifies the commit that introduced it, including the author, date, and commit message — giving context about when and by whom the credential entered the repository.

### Repository Hygiene Checks

The scanner checks for the presence of a `.gitignore` and a license file anywhere in the repository, not just at the root, since many real projects keep these in subfolders.

### Scan History (Per-User)

Every scan is tied to the authenticated account that ran it. Signing in shows only your own scan history, including a risk score trend over time per repository, with the ability to delete individual entries.

### Repository Comparison

Two repositories can be scanned in parallel and compared side by side, including which finding types are unique to each repository and which are shared.

### Real-Time Scan Progress

Scans run over an authenticated WebSocket connection, so the interface shows live per-file progress as the scan runs instead of a single static loading indicator.

### Authentication

Accounts are protected with hashed passwords (bcrypt) and JWT-based session tokens, with the token also validated over the WebSocket connection — not just standard REST routes — since scans and scan history both need to be correctly scoped to the logged-in user.

### Light/Dark Theme

A toggle in the header switches between light and dark color schemes, persisted across sessions.

### Web Interface

Includes a public landing page with a static example scan (no login required to preview what the tool does), a login/signup page, the main scanner dashboard, and a repository comparison page.

### REST API

The backend is built using FastAPI and provides endpoints for authentication, starting scans, retrieving results and confidence/remediation data, comparing repositories, and viewing scan history.

## How it works

```text
GitHub Repository
       |
       v
Repository Fetcher
       |
       v
File Discovery
       |
       +-------------------+
       |                   |
       v                   v
Pattern Detection    Entropy Detection
       |                   |
       +---------+---------+
                 |
                 v
           Finding Analysis
                 |
        +--------+--------+
        |                 |
        v                 v
  Confidence Score   Risk Scoring
        |                 |
        +--------+--------+
                 |
                 v
         Commit Attribution
                 |
                 v
            Scan Results
                 |
          +------+------+
          |             |
          v             v
    Database (per-user)  FastAPI
                             |
                             v
                       Web Interface
```

## Tech Stack

### Backend

* Python
* FastAPI
* WebSockets (real-time scan progress, authenticated)
* PyJWT + bcrypt (authentication)

### Frontend

* HTML
* CSS
* JavaScript
* Chart.js (risk score trend visualization)

### Database

* SQLite

### Other

* GitHub REST API
* Regular expressions
* Shannon entropy
* `python-dotenv`

## Project Structure

```text
credential-scanner/
|
├── api.py
├── auth.py
├── scanner.py
├── patterns.py
├── entropy.py
├── risk.py
├── confidence.py
├── remediation.py
├── github_fetch.py
├── database.py
├── report.py
|
├── static/
│   ├── landing.html
│   ├── login.html
│   ├── login.js
│   ├── index.html
│   ├── compare.html
│   ├── script.js
│   ├── compare.js
│   ├── apiClient.js
│   ├── authGuard.js
│   ├── theme.js
│   ├── style.css
│   └── favicon.ico
|
├── tests/
|
├── requirements.txt
└── README.md
```

## Running the Project

Clone the repository:

```bash
git clone https://github.com/vidya235252-crypto/credential-scanner.git
cd credential-scanner
```

Create a virtual environment:

```bash
python -m venv venv
```

On Windows:

```bash
venv\Scripts\activate
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```env
GITHUB_TOKEN=your_github_token
JWT_SECRET_KEY=your_generated_secret
```

A [personal access token](https://github.com/settings/tokens) with public repository read access is sufficient for `GITHUB_TOKEN`. Generate a real `JWT_SECRET_KEY` with:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Start the FastAPI application:

```bash
uvicorn api:app --reload
```

Visit `http://localhost:8000/welcome` for the landing page, or `http://localhost:8000` to go straight to the app (you'll be redirected to sign up/log in).

## Testing

```bash
pytest
```

Tests cover the pure-function modules (pattern matching, entropy scoring, risk scoring, confidence scoring) with no mocking required. Tests for the network/database-dependent modules (`github_fetch.py`, `database.py`) are a planned next step.

## Deployment

Deployed on [Render](https://render.com). Note: the free tier uses an ephemeral filesystem, meaning the SQLite database resets after periods of inactivity or a redeploy — accounts and scan history won't persist indefinitely on the hosted demo. This is a known tradeoff for the free-tier demo environment, not a bug.

## Limitations

This is a personal/student project and there are still things I want to improve.

* The number of supported credential patterns is still limited.
* Entropy detection can sometimes produce false positives.
* The scanner does not currently verify whether a detected credential is still active.
* Confidence scoring uses a fixed set of signals rather than a trained model.
* CI/CD integration has not been added yet.
* The hosted demo's database resets periodically (free-tier hosting limitation).
* Commit attribution adds one extra API call per file with findings, which can slow down scans of repositories with many findings.

## Future Improvements

* Add more credential patterns
* Add credential validity checks where possible
* Mocking-based tests for network/database modules
* GitHub Actions CI running the test suite on push
* Repository security heatmap and secret clustering
* Downloadable security reports (PDF/CSV)
* False-positive feedback loop to improve confidence scoring over time

## What I Learned

Building this project helped me understand several areas I had mostly studied theoretically before:

* Building APIs with FastAPI
* Working with the GitHub API
* Regular-expression and entropy-based detection
* Designing an explainable scoring system, not just a black-box number
* Git repository analysis
* Database integration, including scoping data per authenticated user
* Concurrent file scanning
* Bridging threaded code with async WebSocket connections
* Implementing JWT authentication across both REST and WebSocket routes
* Password hashing and secure credential handling for the app itself
* Debugging real deployment issues (missing files, environment variables, ephemeral filesystems)
* Thinking about false positives in security tools

## Disclaimer

This project is intended for educational and defensive security purposes.

Only scan repositories that you own or have permission to analyze.

## Author

Vidya

GitHub: https://github.com/vidya235252-crypto
