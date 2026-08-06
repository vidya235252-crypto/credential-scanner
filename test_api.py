import requests

response = requests.get("https://api.github.com")
data = response.json()

print(type(data))
print(data["rate_limit_url"])