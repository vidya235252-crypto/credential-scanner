# RepoSentinel

RepoSentinel is a security-focused web application that scans GitHub repositories for potentially exposed credentials and sensitive information.

I built this project to get hands-on experience with cybersecurity, APIs, backend development, authentication, and GitHub repository analysis.

**Live Demo:** https://credential-scanner.onrender.com/welcome

## Features

* Detects AWS keys, API keys, Slack tokens, private keys, and suspicious high-entropy strings
* Uses pattern matching and entropy-based detection
* Provides explainable confidence scores for each finding
* Assigns risk scores based on finding type
* Gives remediation suggestions for detected credentials
* Shows the commit that introduced a finding when available
* Checks repository security hygiene such as `.gitignore` and license files
* Supports authenticated users and per-user scan history, including GitHub OAuth login
* Compares findings between two repositories
* Shows real-time scan progress using WebSockets
* Supports light and dark themes

## How It Works

```text
GitHub Repository
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
 Confidence Score    Risk Score
        |                 |
        +--------+--------+
                 |
                 v
            Scan Results
```

## Tech Stack

**Backend**

* Python
* FastAPI
* WebSockets
* PyJWT
* bcrypt

**Frontend**

* HTML
* CSS
* JavaScript
* Chart.js

**Database**

* PostgreSQL

**Other**

* GitHub REST API
* Regular expressions
* Shannon entropy

## Project Structure

```text
credential-scanner/
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
├── static/
├── tests/
├── requirements.txt
└── README.md
```

## Running Locally

Clone the repository:

```bash
git clone https://github.com/vidya235252-crypto/credential-scanner.git
cd credential-scanner
```

Create and activate a virtual environment:

```bash
python -m venv venv
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```
This project requires a local PostgreSQL installation. Create a database (e.g. `credential_scanner`) and set `DATABASE_URL` accordingly.

Create a `.env` file:

```env
GITHUB_TOKEN=your_github_token
JWT_SECRET_KEY=your_generated_secret
DATABASE_URL=postgresql://postgres:your_password@localhost:5432/credential_scanner
GITHUB_OAUTH_CLIENT_ID=your_client_id
GITHUB_OAUTH_CLIENT_SECRET=your_client_secret
GITHUB_OAUTH_REDIRECT_URI=http://localhost:8000/auth/github/callback
```

Generate a JWT secret:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Run the application:

```bash
uvicorn api:app --reload
```

Open `http://localhost:8000/welcome`.

## Testing

```bash
pytest
```

Current tests cover the main detection and scoring logic, including pattern matching, entropy, risk, and confidence scoring.

## Limitations

* Credential patterns are still limited.
* Entropy detection can produce false positives.
* Detected credentials are not checked for validity.
* Confidence scoring currently uses fixed rules.
* CI/CD integration is not available yet.

## Future Improvements

* Add more credential patterns
* Add credential validity checks
* Improve test coverage
* Add GitHub Actions CI
* Add security heatmaps
* Add downloadable reports
* Improve false-positive detection

## What I Learned

Building RepoSentinel helped me gain practical experience with:

* FastAPI and REST APIs
* GitHub API integration
* Credential detection and entropy analysis
* JWT authentication and password hashing
* WebSockets and real-time updates
* Database integration
* Git repository analysis
* Debugging and deployment

## Disclaimer

This project is for educational and defensive security purposes.

Only scan repositories that you own or have permission to analyze.

## Author

**Vidya**

GitHub: https://github.com/vidya235252-crypto

