from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import scanner
import database
import github_fetch
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

database.init_db()

class ScanRequest(BaseModel):
    owner: str
    repo: str

@app.post("/scan")
def trigger_scan(request: ScanRequest):
    remaining, limit = github_fetch.check_rate_limit()
    if remaining < 50:
        raise HTTPException(status_code=429, detail="Low on GitHub API requests, try again later")
    
    try:
        findings, skipped, files_scanned, risk_score, hygiene, density = scanner.scan_repo(request.owner, request.repo)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    scan_id = database.save_scan(request.owner, request.repo, findings, len(skipped), risk_score)
    
    return {
    "scan_id": scan_id,
    "owner": request.owner,
    "repo": request.repo,
    "files_scanned": files_scanned,
    "findings_count": len(findings),
    "skipped_count": len(skipped),
    "risk_score": risk_score,
    "secret_density": density,
    "hygiene": hygiene,
    "findings": findings
    }

@app.get("/scans")
def list_scans():
    rows = database.get_all_scans()
    scans = []
    for row in rows:
        scans.append({
            "id": row[0],
            "owner": row[1],
            "repo": row[2],
            "scanned_at": row[3],
            "skipped_count": row[4]
        })
    return scans

@app.delete("/scans/{owner}/{repo}")
def clear_repo_scans(owner: str, repo: str):
    database.clear_scans_for_repo(owner, repo)
    return {"message": f"Scan history cleared for {owner}/{repo}"}

@app.get("/scans/{scan_id}")
def get_scan(scan_id: int):
    rows = database.get_scan_findings(scan_id)
    if not rows:
        raise HTTPException(status_code=404, detail="Scan not found or has no findings")
    
    findings = []
    for row in rows:
        findings.append({
            "file": row[0],
            "type": row[1],
            "match": row[2],
            "method": row[3],
            "severity": row[4]
        })
    return {"scan_id": scan_id, "findings": findings}

@app.get("/scans/history/{owner}/{repo}")
def scan_history(owner: str, repo: str):
    rows = database.get_scan_history_for_repo(owner, repo)
    history = []
    for row in rows:
        history.append({
            "scanned_at": row[0],
            "findings_count": row[1],
            "risk_score": row[2]
        })
    return history

@app.get("/")
def serve_frontend():
    return FileResponse("static/index.html")