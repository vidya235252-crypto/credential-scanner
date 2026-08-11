from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import scanner
import database
import github_fetch
import confidence
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi import WebSocket
import threading
import queue as queue_module

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

database.init_db()

class ScanRequest(BaseModel):
    owner: str
    repo: str

class CompareRequest(BaseModel):
    owner1: str
    repo1: str
    owner2: str
    repo2: str

class FindingInput(BaseModel):
    file: str
    type: str
    match: str
    method: str
    entropy: Optional[float] = None

class ConfidenceRequest(BaseModel):
    findings: List[FindingInput]

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

@app.post("/compare")
def compare_repos_route(request: CompareRequest):
    remaining, limit = github_fetch.check_rate_limit()
    if remaining < 50:
        raise HTTPException(status_code=429, detail="Low on GitHub API requests, try again later")
    
    try:
        result = scanner.compare_repos(request.owner1, request.repo1, request.owner2, request.repo2)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    return result

@app.post("/findings/confidence")
def get_findings_confidence(request: ConfidenceRequest):
    results = []
    for finding in request.findings:
        finding_dict = {"type": finding.type, "match": finding.match, "method": finding.method}
        if finding.entropy is not None:
            finding_dict["entropy"] = finding.entropy
        results.append(confidence.calculate_confidence(finding_dict, finding.file))
    return {"results": results}

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

@app.get("/compare")
def serve_compare_page():
    return FileResponse("static/compare.html")

@app.websocket("/ws/test")
async def websocket_test(websocket: WebSocket):
    await websocket.accept()
    await websocket.send_text("Hello from the server")
    await websocket.close()

@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    await websocket.accept()
    data = await websocket.receive_json()
    owner = data["owner"]
    repo = data["repo"]
    progress_queue = queue_module.Queue()
    def run_scan():
        result = scanner.scan_repo(owner, repo, progress_queue=progress_queue)
        findings, skipped, files_scanned, risk_score, hygiene, density = result
        database.save_scan(owner, repo, findings, len(skipped), risk_score)
        progress_queue.put({"status": "final_result", "result": result})
    thread = threading.Thread(target=run_scan)
    thread.start()
    while True:
        update = progress_queue.get()
        if update.get("status") == "final_result":
            findings, skipped, files_scanned, risk_score, hygiene, density = update["result"]
            await websocket.send_json({
                "status": "complete",
                "findings_count": len(findings),
                "files_scanned": files_scanned,
                "risk_score": risk_score,
                "secret_density": density,
                "hygiene": hygiene,
                "findings": findings
            })
            break
        else:
            await websocket.send_json(update)
    await websocket.close()