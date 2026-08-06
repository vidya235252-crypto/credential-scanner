import requests
import base64

def get_repo_info(owner, repo):
    url = f"https://api.github.com/repos/{owner}/{repo}"
    response = requests.get(url)
    data = response.json()
    return data

def get_file_list(owner, repo):
    tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/master?recursive=1"
    tree_response = requests.get(tree_url)
    tree_data = tree_response.json()
    
    files = []
    for file in tree_data["tree"]:
        files.append({"path": file["path"], "url": file["url"]})
    
    return files

def get_file_content(blob_url):
    blob_response = requests.get(blob_url)
    blob_data = blob_response.json()
    encoded_content = blob_data["content"]
    decoded_bytes = base64.b64decode(encoded_content)
    decoded_text = decoded_bytes.decode("utf-8")
    return decoded_text

info = get_repo_info("octocat", "Hello-World")
print(info["full_name"])
print(info["description"])

files = get_file_list("octocat", "Hello-World")
print(files)

first_file = files[0]
content = get_file_content(first_file["url"])
print(content)