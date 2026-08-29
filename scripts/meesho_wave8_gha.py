#!/usr/bin/env python3
"""Meesho bounty hunt — clean egress probes (route diff only, no exploit payloads)."""
import json
import os
import re
import subprocess
import urllib.parse

OUT_DIR = os.environ.get("OUT_DIR", "artifacts")
os.makedirs(OUT_DIR, exist_ok=True)
R = {"confirmed": [], "leads": [], "probes": {}}


def curl(url, method="GET", body=None, ua="okhttp/4.9.0", timeout=15):
    cmd = [
        "curl", "-sS", "-m", str(timeout), "-A", ua,
        "-w", "\n__C__%{http_code}__",
    ]
    if method != "GET":
        cmd.extend(["-X", method])
    if body is not None:
        cmd.extend(["-H", "Content-Type: application/json", "-d", body])
    cmd.append(url)
    p = subprocess.run(cmd, capture_output=True, text=True)
    m = re.search(r"__C__(\d+)__\s*$", p.stdout)
    body_out = p.stdout[: m.start()] if m else p.stdout
    code = int(m.group(1)) if m else 0
    return code, body_out


# Ignition / admin supply (route differential only)
admin_paths = [
    "/_ignition/health-check",
    "/_ignition/execute-solution",
    "/telescope/requests",
    "/api/google/oauth",
    "/api/health",
    "/sanctum/csrf-cookie",
]
for path in admin_paths:
    url = "https://admin.meeshosupply.com" + path
    for ua in ["okhttp/4.9.0", "Mozilla/5.0"]:
        code, body = curl(url, ua=ua)
        key = f"admin|{ua[:8]}|{path}"
        R["probes"][key] = {"code": code, "body": body[:500]}
        if code not in (403,) and "Access Denied" not in body[:200]:
            R["leads"].append({"host": "admin.meeshosupply.com", "path": path, "ua": ua, "code": code, "body": body[:150]})
        if code == 200 and "ignition" in body.lower():
            R["confirmed"].append({"type": "ignition_health_200", "path": path})

# prod.meeshoapi mobile routes
prod_paths = [
    "/v3/home", "/v4/home", "/mobile/v1/home", "/bff/v1/home",
    "/auth/otp/send", "/health", "/version", "/swagger.json",
]
for path in prod_paths:
    code, body = curl("https://prod.meeshoapi.com" + path)
    R["probes"]["prod" + path] = {"code": code, "body": body[:300]}
    if code == 200 and len(body) > 20:
        R["leads"].append({"type": "prod_api_200", "path": path, "body": body[:150]})

# supplier ignition
for path in ["/_ignition/health-check", "/api/health"]:
    code, body = curl("https://supplier.meesho.com" + path)
    R["probes"]["supplier" + path] = {"code": code, "body": body[:300]}
    if code not in (403, 404):
        R["leads"].append({"host": "supplier.meesho.com", "path": path, "code": code})

# Instagram OAuth redirect_uri (Meta-side check)
client = "3358928634404127"
scope = urllib.parse.quote("instagram_business_basic")
for ru in [
    "https://affiliate.meesho.com/oauth-bridge",
    "https://evil.example/callback",
]:
    url = (
        f"https://www.instagram.com/oauth/authorize?client_id={client}"
        f"&response_type=code&scope={scope}&redirect_uri={urllib.parse.quote(ru, safe='')}"
    )
    p = subprocess.run(["curl", "-sS", "-m", "12", "-I", url], capture_output=True, text=True)
    loc = [l.strip() for l in p.stdout.splitlines() if l.lower().startswith("location:")]
    R["probes"]["ig_oauth_" + ru[:30]] = {"location": loc[:1]}
    if loc and "evil.example" in loc[0] and "evil" in ru:
        R["confirmed"].append({"type": "instagram_redirect_uri_bypass", "redirect_uri": ru, "location": loc[0]})

out_path = os.path.join(OUT_DIR, "meesho_wave8_gha.json")
with open(out_path, "w") as f:
    json.dump(R, f, indent=2)

print(json.dumps({"confirmed": len(R["confirmed"]), "leads": len(R["leads"]), "out": out_path}))
