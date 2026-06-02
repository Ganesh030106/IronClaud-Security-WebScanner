import sys
sys.path.append('e:/Firewall-main/Web_scanner/backend')
from fastapi.testclient import TestClient
from main import app
import os

client = TestClient(app)

print("--- Testing /api/waf/config ---")
response = client.get("/api/waf/config")
print("Response status:", response.status_code)
print("Response JSON:", response.json())
assert response.status_code == 200

print("\n--- Testing /api/waf/config/whitelist ---")
response = client.post("/api/waf/config/whitelist", json={"ip": "127.0.0.1"})
print("Response status:", response.status_code)
print("Response JSON:", response.json())
assert response.status_code == 200
assert "127.0.0.1" in response.json()["whitelist"]

print("\n--- Testing /api/waf/config/blacklist ---")
response = client.post("/api/waf/config/blacklist", json={"ip": "8.8.8.8"})
print("Response status:", response.status_code)
print("Response JSON:", response.json())
assert response.status_code == 200
assert "8.8.8.8" in response.json()["blacklist"]

print("\n--- Testing /api/waf/config/whitelist DELETE ---")
response = client.delete("/api/waf/config/whitelist/127.0.0.1")
print("Response status:", response.status_code)
print("Response JSON:", response.json())
assert response.status_code == 200
assert "127.0.0.1" not in response.json()["whitelist"]

print("\n--- Testing /api/waf/config/blacklist DELETE ---")
response = client.delete("/api/waf/config/blacklist/8.8.8.8")
print("Response status:", response.status_code)
print("Response JSON:", response.json())
assert response.status_code == 200
assert "8.8.8.8" not in response.json()["blacklist"]

print("\n--- Testing /api/ai/status ---")
response = client.get("/api/ai/status")
print("Response status:", response.status_code)
print("Response keys:", list(response.json().keys()))
assert response.status_code == 200

print("\n--- Testing /api/ai/config/reset ---")
response = client.post("/api/ai/config/reset")
print("Response status:", response.status_code)
print("Response JSON:", response.json())
assert response.status_code == 200

print("\nALL BACKEND ENDPOINT TESTS PASSED SUCCESSFULLY!")
