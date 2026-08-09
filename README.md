# Credential Scanner

A security-focused web application that scans GitHub repositories for potentially exposed credentials and sensitive information.

I built this project to understand how secret scanning works and to get practical experience with cybersecurity, APIs, backend development, and GitHub repository analysis.

## What it does

The scanner checks files in a GitHub repository for possible credentials and assigns a risk score to the findings.

The main detection methods currently used are:

* Pattern-based detection for known credential formats
* Entropy-based detection for suspicious random-looking strings
* Risk scoring based on the type of finding
* Repository security checks
* Commit-level attribution for detected findings
* Scan history and stored results

## Main Features

### Credential Detection

The scanner currently looks for different types of credentials and sensitive information, including:

* AWS credentials
* API keys
* Slack tokens
* Private keys
* Generic sensitive tokens

The detection is mainly based on predefined patterns.

### Entropy Detection

Not every secret follows a known pattern.

The scanner also checks for high-entropy strings that could potentially be secrets. This helps identify suspicious values that might not match one of the predefined patterns.

### Risk Scoring

Different findings have different levels of importance.

For example, a private key should generally be treated as more serious than a generic high-entropy string. The project therefore assigns scores to different types of findings and uses them to calculate an overall risk level.

### Secret Density

Findings are also expressed relative to repository size (findings per 100 files scanned), which makes it possible to compare repositories of different sizes on a fairer basis than raw finding counts alone.

### Commit Attribution

When a potential credential is found, the scanner attempts to identify the commit that introduced it, including the author, date, and commit message. This gives additional context about when and by whom the credential entered the repository.

### Repository Hygiene Checks

The scanner checks for the presence of a `.gitignore` and a license file anywhere in the repository, not just at the root, since many real projects keep these in subfolders.

### Scan History

Previous scans and their results are stored so that they can be reviewed later, including a per-repository risk score trend over time and the ability to clear history for a specific repository.

### Repository Comparison

Two repositories can be scanned in parallel and compared side by side, including which finding types are unique to each repository and which are shared.

### Real-Time Scan Progress

Scans run over a WebSocket connection, so the interface shows live progress as each file is scanned instead of a single static loading indicator.

### Web Interface

The project has a frontend where a repository can be scanned and the results can be viewed.

### REST API

The backend is built using FastAPI and provides endpoints for starting scans, retrieving results, comparing repositories, and viewing scan history.

## How it works

The basic flow of the application is:

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
                 v
            Risk Scoring
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
       Database      FastAPI
                        |
                        v
                  Web Interface
```

## Tech Stack

### Backend

* Python
* FastAPI
* WebSockets (real-time scan progress)

### Frontend

* HTML
* CSS
* JavaScript
* Chart.js (risk score trend visualization)

### Database

* SQLite

### Other

* GitHub API
* Regular expressions
* Entropy analysis
* Git/GitHub repository analysis

## Project Structure

```text
credential-scanner/
|
├── api.py
├── scanner.py
├── patterns.py
├── entropy.py
├── risk.py
├── github_fetch.py
├── database.py
├── report.py
|
├── static/
│   ├── index.html
│   ├── compare.html
│   ├── script.js
│   ├── compare.js
│   └── style.css
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

Create a `.env` file in the project root with your GitHub token:

```env
GITHUB_TOKEN=your_github_token
```

A [personal access token](https://github.com/settings/tokens) with public repository read access is sufficient.

Start the FastAPI application:

```bash
uvicorn api:app --reload
```

The application can then be accessed locally through the FastAPI server.

## Testing

Tests are included for parts of the application.

To run them:

```bash
pytest
```

## Limitations

This is a personal/student project and there are still several things I want to improve.

Some current limitations are:

* The number of supported credential patterns is still limited.
* Entropy detection can sometimes produce false positives.
* The scanner does not currently verify whether a detected credential is still active.
* Git history scanning can be improved further.
* The current risk scoring system is relatively simple.
* CI/CD integration has not been added yet.
* Commit attribution adds one extra API call per file with findings, which can slow down scans of repositories with many findings.

## Future Improvements

Some improvements I would like to work on:

* Add more credential patterns
* Improve false-positive detection
* Add confidence scoring
* Improve Git history scanning
* Add credential validity checks where possible
* Add GitHub Actions integration
* Add pre-commit support
* Improve the risk scoring system
* Add better security reports
* Add notifications for high-risk findings

## What I Learned

Building this project helped me understand several areas that I had mostly studied theoretically before.

Some of the main things I worked with were:

* Building APIs with FastAPI
* Working with the GitHub API
* Regular-expression based detection
* Entropy-based analysis
* Git repository analysis
* Risk scoring
* Database integration
* Concurrent file scanning
* Bridging threaded code with async WebSocket connections
* Connecting a frontend with a backend
* Thinking about false positives in security tools

## Disclaimer

This project is intended for educational and defensive security purposes.

Only scan repositories that you own or have permission to analyze.

## Author

Vidya

GitHub: https://github.com/vidya235252-crypto
