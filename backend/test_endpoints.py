import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from fastapi.testclient import TestClient
from main import app


client = TestClient(app)

print("--- Testing HTTP Security Headers Middleware ---")
response = client.get("/api/health")
print("Response headers:", dict(response.headers))
assert response.headers.get("x-content-type-options") == "nosniff"
assert response.headers.get("x-frame-options") == "DENY"
assert "strict-transport-security" in response.headers
print("Security headers verified!")

print("\n--- Testing Root and Health Ping Endpoints ---")
res_root = client.get("/")
assert res_root.status_code == 200
assert res_root.json()["status"] == "online"

res_root_head = client.head("/")
assert res_root_head.status_code == 200

res_health = client.get("/health")
assert res_health.status_code == 200
assert res_health.json()["status"] == "ok"

res_api_health_head = client.head("/api/health")
assert res_api_health_head.status_code == 200
print("Root and Health endpoints verified!")

print("\n--- Testing SSRF & Private Target Blocking ---")
res_local = client.post("/api/scan", json={"url": "http://127.0.0.1:8000"})
assert res_local.status_code == 400
print("Blocked 127.0.0.1:", res_local.json()["detail"])

res_meta = client.post("/api/scan", json={"url": "http://169.254.169.254/latest/meta-data"})
assert res_meta.status_code == 400
print("Blocked cloud metadata:", res_meta.json()["detail"])

res_localhost = client.post("/api/scan", json={"url": "http://localhost/admin"})
assert res_localhost.status_code == 400
print("Blocked localhost:", res_localhost.json()["detail"])
print("SSRF protection verified!")

print("\n--- Testing /api/waf/config ---")
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

print("\n--- Testing /api/scan with scan_mode ---")
import main
orig_run = main.run_scan_task
main.run_scan_task = lambda url, scan_mode="deep": None
try:
    response = client.post("/api/scan", json={"url": "http://example.com", "scan_mode": "quick"})
    print("Response status:", response.status_code)
    print("Response JSON:", response.json())
    assert response.status_code == 200
    assert response.json()["status"] == "scanning"
    assert response.json().get("scan_mode") == "quick"
finally:
    main.run_scan_task = orig_run

print("\n--- Testing OWASPTester scan_mode ---")
from scanner import OWASPTester
tester_quick = OWASPTester("http://example.com", scan_mode="quick")
assert tester_quick.scan_mode == "quick"
assert tester_quick.results["info"]["scan_mode"] == "quick"
print("Quick mode verified!")

tester_deep = OWASPTester("http://example.com", scan_mode="deep")
assert tester_deep.scan_mode == "deep"
assert tester_deep.results["info"]["scan_mode"] == "deep"
print("Deep mode verified!")

print("\n--- Testing FuzzingEngine Module ---")
from modules.fuzzing_engine import FuzzingEngine
import requests
engine = FuzzingEngine(requests.Session(), "http://example.com")
assert hasattr(engine, "check_ssrf")
assert hasattr(engine, "check_path_traversal")
assert hasattr(engine, "check_nosql_injection")
assert hasattr(engine, "check_xxe")
assert hasattr(engine, "check_cache_poisoning")
assert hasattr(engine, "check_insecure_deserialization")
print("FuzzingEngine methods verified!")

print("\nALL BACKEND ENDPOINT & MODULE TESTS PASSED SUCCESSFULLY!", flush=True)
os._exit(0)

