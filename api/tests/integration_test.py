#!/usr/bin/env python3
"""
Simple integration test for /auth/login and /settings/close-hour against a deployed instance.
Reads these secrets from the environment (set them in GitHub Actions secrets):
- DEPLOYED_BASE_URL (e.g. https://aronium-sync.onrender.com)
- INTEGRATION_TAX
- INTEGRATION_PASSWORD

Exits non-zero on failure.
"""
import os
import sys
import requests

BASE = os.environ.get("DEPLOYED_BASE_URL")
TAX = os.environ.get("INTEGRATION_TAX")
PWD = os.environ.get("INTEGRATION_PASSWORD")

if not BASE or not TAX or not PWD:
    print("Missing DEPLOYED_BASE_URL or INTEGRATION_TAX or INTEGRATION_PASSWORD")
    sys.exit(2)

login_url = BASE.rstrip("/") + "/api/portal/auth/login"
close_url = BASE.rstrip("/") + "/api/portal/settings/close-hour"

s = requests.Session()
try:
    r = s.post(login_url, json={"username": TAX, "password": PWD}, timeout=15)
    r.raise_for_status()
except Exception as e:
    print("Login request failed:", e)
    sys.exit(3)

data = r.json()
if "token" not in data:
    print("Login response missing token; response:", data)
    sys.exit(4)

token = data["token"]
headers = {"Authorization": f"Bearer {token}"}
try:
    r2 = s.post(close_url, json={"close_hour": 1}, headers=headers, timeout=15)
    r2.raise_for_status()
except Exception as e:
    print("Close-hour request failed:", e)
    sys.exit(5)

print("Integration test succeeded: login and close-hour update returned", r2.status_code)
sys.exit(0)
