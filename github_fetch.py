import requests
import base64
import os
from dotenv import load_dotenv

load_dotenv()

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

HEADERS = {
    "Authorization": f"token {GITHUB_TOKEN}"
}

def get_repo_info(owner, repo):
    url = f"https://api.github.com/repos/{owner}/{repo}"
    response = requests.get(url, headers=HEADERS)
    data = response.json()
    return data

def get_file_list(owner, repo, branch="main"):
    tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    tree_response = requests.get(tree_url, headers=HEADERS)
    tree_data = tree_response.json()
    
    if tree_data.get("truncated"):
        print(f"WARNING: File list for {owner}/{repo} was truncated. Not all files were scanned.")
    
    files = []
    for file in tree_data["tree"]:
        files.append({"path": file["path"], "url": file["url"]})
    
    return files

def get_file_content(blob_url):
    blob_response = requests.get(blob_url, headers=HEADERS)
    blob_data = blob_response.json()
    encoded_content = blob_data["content"]
    decoded_bytes = base64.b64decode(encoded_content)
    decoded_text = decoded_bytes.decode("utf-8")
    return decoded_text

def get_file_history(owner, repo, path):
    url = f"https://api.github.com/repos/{owner}/{repo}/commits"
    params = {"path": path}
    response = requests.get(url, headers=HEADERS, params=params)
    return response.json()

def get_introducing_commit(owner, repo, path):
    history = get_file_history(owner, repo, path)
    
    if not history:
        return None
    
    oldest_commit = history[-1]
    
    return {
        "sha": oldest_commit["sha"],
        "author": oldest_commit["commit"]["author"]["name"],
        "date": oldest_commit["commit"]["author"]["date"],
        "message": oldest_commit["commit"]["message"]
    }

if __name__ == "__main__":
    info = get_repo_info("octocat", "Hello-World")
    print(info["full_name"])
    print(info["description"])
    
    branch = info["default_branch"]
    files = get_file_list("octocat", "Hello-World", branch)
    print(files)
    
    first_file = files[0]
    content = get_file_content(first_file["url"])
    print(content)

def check_rate_limit():
    response = requests.get("https://api.github.com/rate_limit", headers=HEADERS)
    data = response.json()
    remaining = data["rate"]["remaining"]
    limit = data["rate"]["limit"]
    return remaining, limit

def file_exists(owner, repo, path):
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    response = requests.get(url, headers=HEADERS)
    return response.status_code == 200

def check_hygiene(file_paths):
    has_gitignore = any(
        path == ".gitignore" or path.endswith("/.gitignore")
        for path in file_paths
    )
    has_license = any(
        path.split("/")[-1] in ("LICENSE", "LICENSE.md")
        for path in file_paths
    )
    
    return {
        "has_gitignore": has_gitignore,
        "has_license": has_license
    }

def fetch_user_public_repos(github_access_token):
    headers = {"Authorization": f"Bearer {github_access_token}"}
    response = requests.get(
        "https://api.github.com/user/repos",
        headers=headers,
        params={"type": "owner", "sort": "updated", "per_page": 100}
    )
    data = response.json()

    if isinstance(data, dict) and "message" in data:
        return {"error": data["message"]}

    repos = [
        {"owner": repo["owner"]["login"], "repo": repo["name"], "full_name": repo["full_name"]}
        for repo in data
        if not repo.get("private", False)
    ]
    return {"repos": repos}