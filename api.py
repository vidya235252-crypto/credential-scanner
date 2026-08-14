from fastapi import FastAPI, HTTPException, Depends
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
import remediation
import auth
from fastapi import Request
from fastapi.responses import RedirectResponse
import secrets

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

database.init_db()

class ScanRequest(BaseModel):
    owner: str
    repo: str

class SignupRequest(BaseModel):
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

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

@app.post("/auth/signup")
def signup(request: SignupRequest):
    existing = database.get_user_by_email(request.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    password_hash = auth.hash_password(request.password)
    user_id = database.create_user(request.email, password_hash)
    token = auth.create_access_token(user_id, request.email)
    return {"access_token": token, "token_type": "bearer"}

@app.get("/auth/github/login")
def github_login():
    state = secrets.token_urlsafe(24)
    url = auth.build_github_authorize_url(state)
    response = RedirectResponse(url)
    response.set_cookie("github_oauth_state", state, httponly=True, max_age=600, samesite="lax")
    return response


@app.get("/auth/github/callback")
def github_callback(code: str, state: str, request: Request):
    cookie_state = request.cookies.get("github_oauth_state")
    if not cookie_state or cookie_state != state:
        raise HTTPException(status_code=400, detail="Invalid OAuth state")

    github_access_token = auth.exchange_github_code(code)
    github_user = auth.get_github_user(github_access_token)

    if not github_user["email"]:
        raise HTTPException(status_code=400, detail="GitHub account has no verified email")

    existing_by_github = database.get_user_by_github_id(github_user["github_id"])
    if existing_by_github:
        user_id, user_email = existing_by_github[0], existing_by_github[1]
        database.link_github_to_user(user_id, github_user["github_id"], github_access_token)
    else:
        existing_by_email = database.get_user_by_email(github_user["email"])
        if existing_by_email:
            database.link_github_to_user(existing_by_email[0], github_user["github_id"], github_access_token)
            user_id, user_email = existing_by_email[0], existing_by_email[1]
        else:
            user_id = database.create_user_from_github(github_user["email"], github_user["github_id"], github_access_token)
            user_email = github_user["email"]

    jwt_token = auth.create_access_token(user_id, user_email)
    response = RedirectResponse(f"/static/oauth-complete.html?token={jwt_token}")
    response.delete_cookie("github_oauth_state")
    return response

@app.post("/auth/login")
def login(request: LoginRequest):
    user = database.get_user_by_email(request.email)
    if not user or not user[2] or not auth.verify_password(request.password, user[2]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = auth.create_access_token(user[0], user[1])
    return {"access_token": token, "token_type": "bearer"}

@app.post("/scan")
def trigger_scan(request: ScanRequest, current_user: dict = Depends(auth.get_current_user)):
    remaining, limit = github_fetch.check_rate_limit()
    if remaining < 50:
        raise HTTPException(status_code=429, detail="Low on GitHub API requests, try again later")
    
    try:
        findings, skipped, files_scanned, risk_score, hygiene, density = scanner.scan_repo(request.owner, request.repo)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    scan_id = database.save_scan(request.owner, request.repo, findings, len(skipped), risk_score, current_user["id"])
    
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
def compare_repos_route(request: CompareRequest, current_user: dict = Depends(auth.get_current_user)):
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
def list_scans(current_user: dict = Depends(auth.get_current_user)):
    rows = database.get_all_scans(current_user["id"])
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
def clear_repo_scans(owner: str, repo: str, current_user: dict = Depends(auth.get_current_user)):
    database.clear_scans_for_repo(owner, repo, current_user["id"])
    return {"message": f"Scan history cleared for {owner}/{repo}"}

@app.get("/scans/{scan_id}")
def get_scan(scan_id: int, current_user: dict = Depends(auth.get_current_user)):
    rows = database.get_scan_findings(scan_id, current_user["id"])
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
def scan_history(owner: str, repo: str, current_user: dict = Depends(auth.get_current_user)):
    rows = database.get_scan_history_for_repo(owner, repo, current_user["id"])
    history = []
    for row in rows:
        history.append({
            "scanned_at": row[0],
            "findings_count": row[1],
            "risk_score": row[2]
        })
    return history

@app.get("/github/repos")
def get_github_repos(current_user: dict = Depends(auth.get_current_user)):
    token = database.get_github_access_token(current_user["id"])
    if not token:
        return {"connected": False, "repos": []}

    result = github_fetch.fetch_user_public_repos(token)
    if "error" in result:
        return {"connected": False, "repos": [], "error": result["error"]}

    return {"connected": True, "repos": result["repos"]}

@app.get("/")
def serve_frontend():
    return FileResponse("static/scanner.html")

@app.get("/dashboard")
def serve_dashboard():
    return FileResponse("static/index.html")

@app.get("/compare")
def serve_compare_page():
    return FileResponse("static/compare.html")

@app.get("/remediation")
def get_remediation_map():
    return {
        "recommendations": remediation.REMEDIATION_RECOMMENDATIONS,
        "default": remediation.DEFAULT_RECOMMENDATIONS
    }

@app.get("/login")
def serve_login_page():
    return FileResponse("static/login.html")

@app.get("/welcome")
def serve_landing_page():
    return FileResponse("static/scanner.html")

@app.websocket("/ws/test")
async def websocket_test(websocket: WebSocket):
    await websocket.accept()
    await websocket.send_text("Hello from the server")
    await websocket.close()

@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    await websocket.accept()
    data = await websocket.receive_json()

    token = data.get("token")
    if not token:
        await websocket.send_json({"status": "error", "message": "Missing authentication token"})
        await websocket.close(code=4001)
        return

    try:
        payload = auth.decode_access_token(token)
    except HTTPException:
        await websocket.send_json({"status": "error", "message": "Invalid or expired token"})
        await websocket.close(code=4001)
        return

    user_id = int(payload["sub"])
    owner = data["owner"]
    repo = data["repo"]
    progress_queue = queue_module.Queue()

    def run_scan():
        result = scanner.scan_repo(owner, repo, progress_queue=progress_queue)
        findings, skipped, files_scanned, risk_score, hygiene, density = result
        database.save_scan(owner, repo, findings, len(skipped), risk_score, user_id)
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