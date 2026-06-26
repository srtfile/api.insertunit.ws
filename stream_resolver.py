#!/usr/bin/env python3
"""
stream_resolver.py
==================
Extracts the top-level playable stream URLs from an embed/player page.

Outputs ONLY:
  - MPD manifests (DASH)
  - Master HLS playlists (.m3u8 that are NOT child index-vN / index-aN variants)
  - Direct MP4 / WebM URLs that appear in the page body (not segment templates)
  - iframe / nested player URLs

Does NOT expand manifests (no child playlist fetching → minimal requests).
Does NOT output audio-only child playlists, segment templates, or init fragments.

Usage
-----
CLI (GitHub Actions / local):
    python stream_resolver.py --url "https://api.insertunit.ws/embed/imdb/tt0373074"
    python stream_resolver.py --url "..." --json          # machine-readable JSON
    python stream_resolver.py --serve                     # HTTP API on :8787

Webpage:
    python stream_resolver.py --build-html > resolver.html
    # then open resolver.html in a browser (fetches via a local proxy endpoint
    # that you start with --serve, or via a deployed instance)
"""

from __future__ import annotations

import argparse
import html
import http.cookiejar
import http.server
import json
import re
import socketserver
import sys
import traceback
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)

TEXT_TYPES = (
    "text/",
    "application/json",
    "application/javascript",
    "text/javascript",
    "application/xml",
    "text/xml",
    "application/dash+xml",
    "application/vnd.apple.mpegurl",
    "application/x-mpegurl",
)

# Matches URLs in JS/HTML source
URL_RE = re.compile(r"""(?i)\b(?:https?:)?//[^\s"'<>\\)]{8,}""")
SRC_RE = re.compile(r"""(?is)\b(?:src|href|data-src)\s*=\s*["']([^"']{8,})["']""")

# Child variant filenames we explicitly EXCLUDE from output
CHILD_VARIANT_RE = re.compile(
    r"/index-[av]\d+\.m3u8|"           # index-a7.m3u8, index-v2.m3u8
    r"/chunklist[^/]*\.m3u8|"          # chunklist_b1234.m3u8
    r"/media_\d+\.m3u8|"               # media_0.m3u8
    r"/\d+p\.m3u8|"                    # 720p.m3u8
    r"init\.webm|"                      # DASH init segment
    r"\$Number\$",                      # DASH segment template
    re.I,
)

# What we WANT
MASTER_M3U8_RE  = re.compile(r"\.m3u8(?:[?#]|$)", re.I)
MPD_RE          = re.compile(r"\.mpd(?:[?#]|$)", re.I)
MP4_RE          = re.compile(r"\.mp4(?:[?#]|$)", re.I)
WEBM_DIRECT_RE  = re.compile(r"\.webm(?:[?#]|$)", re.I)   # only if NOT a template
IFRAME_RE       = re.compile(r"(?i)(embed|iframe|player|stream|watch)", )

PROTECTION_RE = {
    "captcha"  : re.compile(r"captcha|hcaptcha|recaptcha|turnstile", re.I),
    "drm"      : re.compile(r"widevine|playready|fairplay|ContentProtection|licenseUrl|drm", re.I),
    "login"    : re.compile(r"login|sign.?in|authentication required|unauthorized", re.I),
    "anti_bot" : re.compile(r"cloudflare|cf-chl|bot.?detection|access denied|forbidden|challenge-platform", re.I),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def uniq(items: Iterable[str]) -> List[str]:
    seen: set = set()
    out = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def normalize_url(raw: str, base: Optional[str] = None) -> str:
    url = html.unescape((raw or "").strip().strip("'\""))
    if url.startswith("//"):
        url = "https:" + url
    if base and not url.startswith(("http://", "https://")):
        url = urllib.parse.urljoin(base, url)
    return url


def is_child_variant(url: str) -> bool:
    """True for child HLS/DASH variants we do NOT want."""
    path = urllib.parse.urlparse(url).path
    return bool(CHILD_VARIANT_RE.search(path + url))


def classify(url: str) -> Optional[str]:
    """
    Returns one of: 'mpd', 'hls', 'mp4', 'iframe', None.
    Returns None if the URL should be ignored.
    """
    if is_child_variant(url):
        return None
    path = urllib.parse.urlparse(url).path.lower()
    if MPD_RE.search(path):
        return "mpd"
    if MASTER_M3U8_RE.search(path):
        return "hls"
    if MP4_RE.search(path):
        return "mp4"
    # webm direct (not a template – already excluded above)
    if WEBM_DIRECT_RE.search(path) and "$" not in url:
        return "webm"
    return None


def extract_all_urls(text: str, base: Optional[str] = None) -> List[str]:
    found = []
    for m in URL_RE.findall(text):
        found.append(normalize_url(m, base))
    for m in SRC_RE.findall(text):
        found.append(normalize_url(m, base))
    return uniq(found)


def detect_protections(text: str, status: Optional[int] = None) -> Dict[str, Any]:
    hits = {}
    for name, pat in PROTECTION_RE.items():
        if pat.search(text or ""):
            hits[name] = True
    if status in (401, 403, 429):
        hits[f"http_{status}"] = True
    return {"blocked": bool(hits), "signals": hits}


def is_text_response(content_type: str, url: str) -> bool:
    ct = (content_type or "").lower()
    path = urllib.parse.urlparse(url).path.lower()
    return (
        any(ct.startswith(t) or t in ct for t in TEXT_TYPES)
        or path.endswith((".html", ".js", ".json", ".xml", ".m3u8", ".mpd", ".txt"))
    )


# ---------------------------------------------------------------------------
# Fetcher
# ---------------------------------------------------------------------------

class Fetcher:
    def __init__(self, timeout: int = 20):
        self.timeout = timeout
        jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def _headers(self, url: str, referer: Optional[str] = None) -> Dict[str, str]:
        h: Dict[str, str] = {
            "User-Agent": DEFAULT_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if referer:
            h["Referer"] = referer
            p = urllib.parse.urlparse(referer)
            if p.scheme and p.netloc:
                h["Origin"] = f"{p.scheme}://{p.netloc}"
        return h

    def get(self, url: str, referer: Optional[str] = None, max_bytes: int = 1_500_000) -> Tuple[int, str, str, str]:
        """Returns (status, content_type, text, final_url)."""
        req = urllib.request.Request(url, headers=self._headers(url, referer))
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                chunks = []
                remaining = max_bytes
                while remaining > 0:
                    chunk = resp.read(min(65536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                data = b"".join(chunks)
                ct = resp.headers.get("Content-Type", "")
                text = data.decode("utf-8", "replace") if is_text_response(ct, url) else ""
                return resp.status, ct, text, resp.geturl()
        except urllib.error.HTTPError as exc:
            data = exc.read(32768)
            ct = exc.headers.get("Content-Type", "") if exc.headers else ""
            text = data.decode("utf-8", "replace") if is_text_response(ct, url) else ""
            return exc.code, ct, text, exc.geturl() or url
        except Exception as exc:
            return 0, "", "", url


# ---------------------------------------------------------------------------
# Core resolver  (2 HTTP requests max: embed page + nothing else by default)
# ---------------------------------------------------------------------------

def resolve(url: str, timeout: int = 20) -> Dict[str, Any]:
    """
    Fetch the embed page once.  Extract and classify all URLs found in the
    HTML/JS source.  Return only the top-level playable stream URLs.
    """
    fetcher = Fetcher(timeout=timeout)
    status, ct, text, final_url = fetcher.get(url)

    result: Dict[str, Any] = {
        "input_url"   : url,
        "final_url"   : final_url,
        "status"      : "ok",
        "http_status" : status,
        "protections" : detect_protections(text, status),
        # ---- main outputs ----
        "mpd"         : [],   # DASH manifests
        "hls"         : [],   # master HLS playlists
        "mp4"         : [],   # direct MP4 URLs
        "webm"        : [],   # direct WebM URLs (non-template)
        "iframe"      : [],   # nested embed / player URLs
        "all_streams" : [],   # flat ordered list for quick use
        "errors"      : [],
    }

    if status == 0:
        result["errors"].append("Network error – could not fetch the page.")
        result["status"] = "error"
        return result

    if result["protections"]["blocked"]:
        result["status"] = "blocked"

    if not text:
        result["errors"].append(f"No text body returned (status {status}, type {ct}).")
        result["status"] = "error"
        return result

    # --- scan all URLs found in the page source ---
    candidates = extract_all_urls(text, final_url)

    for candidate in candidates:
        kind = classify(candidate)
        if kind in ("mpd", "hls", "mp4", "webm"):
            result[kind].append(candidate)   # type: ignore[index]

    # iframes: any URL that still has embed-like path AND is not already a media URL
    media_set = set(result["mpd"] + result["hls"] + result["mp4"] + result["webm"])
    for candidate in candidates:
        parsed = urllib.parse.urlparse(candidate)
        if (
            candidate not in media_set
            and parsed.scheme in ("http", "https")
            and IFRAME_RE.search(parsed.path)
            and not is_child_variant(candidate)
        ):
            result["iframe"].append(candidate)

    # deduplicate
    for key in ("mpd", "hls", "mp4", "webm", "iframe"):
        result[key] = uniq(result[key])   # type: ignore[assignment]

    # flat list: DASH first, then HLS, then MP4, then WebM, then iframes
    result["all_streams"] = uniq(
        result["mpd"] + result["hls"] + result["mp4"] + result["webm"] + result["iframe"]
    )

    if not result["all_streams"] and result["status"] == "ok":
        result["status"] = "no_streams_found"

    return result


# ---------------------------------------------------------------------------
# CLI output
# ---------------------------------------------------------------------------

def print_result(data: Dict[str, Any], as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
        return

    def section(title: str, urls: List[str]) -> None:
        if not urls:
            return
        print(f"\n── {title} ──")
        for u in urls:
            print(f"  {u}")

    print(f"\nStatus  : {data['status']}")
    print(f"Page    : {data['final_url']}  [{data['http_status']}]")
    if data["protections"]["blocked"]:
        print(f"⚠ Protection signals: {list(data['protections']['signals'].keys())}")
    if data["errors"]:
        for e in data["errors"]:
            print(f"✖ {e}", file=sys.stderr)

    section("DASH (MPD)",        data["mpd"])
    section("HLS master (M3U8)", data["hls"])
    section("Direct MP4",        data["mp4"])
    section("Direct WebM",       data["webm"])
    section("Nested iframes",    data["iframe"])

    if not data["all_streams"]:
        print("\n(no streams found)")
    else:
        print(f"\n✔ {len(data['all_streams'])} stream URL(s) found")

    # GitHub Actions output – write to GITHUB_OUTPUT if available
    gho = Path(sys.argv[0]).parent / "stream_urls.json" if not sys.stdout.isatty() else None
    github_output = Path(
        __import__("os").environ.get("GITHUB_OUTPUT", "")
    ) if __import__("os").environ.get("GITHUB_OUTPUT") else None

    if github_output:
        with github_output.open("a") as fh:
            fh.write(f"streams={json.dumps(data['all_streams'])}\n")
            fh.write(f"mpd={json.dumps(data['mpd'])}\n")
            fh.write(f"hls={json.dumps(data['hls'])}\n")
            fh.write(f"mp4={json.dumps(data['mp4'])}\n")


# ---------------------------------------------------------------------------
# HTTP API server  (for --serve and the webpage frontend)
# ---------------------------------------------------------------------------

class ResolveHandler(http.server.BaseHTTPRequestHandler):
    timeout_sec: int = 20

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)

        # Serve the built-in webpage at /
        if parsed.path in ("/", "/index.html"):
            page = build_html()
            self._respond(200, "text/html; charset=utf-8", page.encode())
            return

        if parsed.path == "/resolve":
            qs = urllib.parse.parse_qs(parsed.query)
            target = (qs.get("url") or [""])[0]
            if not target:
                self._json({"error": "missing ?url= parameter"}, 400)
                return
            try:
                data = resolve(target, timeout=self.timeout_sec)
                self._json(data)
            except Exception as exc:
                self._json({"error": str(exc), "trace": traceback.format_exc()}, 500)
            return

        self._json({"error": "not found", "endpoints": ["/", "/resolve?url=..."]}, 404)

    def _json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False, indent=2).encode()
        self._respond(status, "application/json; charset=utf-8", body)

    def _respond(self, status: int, ct: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        pass   # silence access log


def serve(host: str, port: int, timeout: int) -> None:
    import os
    # Render (and most PaaS) injects PORT; honour it so health checks pass.
    port = int(os.environ.get("PORT", port))
    # Render requires binding to 0.0.0.0, not 127.0.0.1.
    host = os.environ.get("HOST", host)
    ResolveHandler.timeout_sec = timeout
    with socketserver.ThreadingTCPServer((host, port), ResolveHandler) as srv:
        srv.allow_reuse_address = True
        print(f"Stream resolver running at  http://{host}:{port}/")
        print(f"API endpoint:               http://{host}:{port}/resolve?url=<embed_url>")
        srv.serve_forever()


# ---------------------------------------------------------------------------
# Self-contained HTML page  (--build-html)
# ---------------------------------------------------------------------------

def build_html() -> str:
    return r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Stream Resolver</title>
<style>
  :root {
    --bg: #0f1117; --surface: #1a1d27; --border: #2a2d3a;
    --accent: #6c8ef7; --green: #4ade80; --red: #f87171;
    --yellow: #fbbf24; --text: #e2e8f0; --muted: #64748b;
    --radius: 10px; --font: 'Inter', system-ui, sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font);
         min-height: 100vh; padding: 24px 16px; }
  h1 { font-size: 1.5rem; font-weight: 700; color: var(--accent);
       margin-bottom: 4px; }
  .sub { color: var(--muted); font-size: 0.85rem; margin-bottom: 24px; }
  .card { background: var(--surface); border: 1px solid var(--border);
          border-radius: var(--radius); padding: 20px; margin-bottom: 16px; }
  .input-row { display: flex; gap: 10px; flex-wrap: wrap; }
  input[type=text] {
    flex: 1; min-width: 240px; background: var(--bg); border: 1px solid var(--border);
    border-radius: 8px; color: var(--text); font-size: 0.9rem;
    padding: 10px 14px; outline: none;
    transition: border-color .2s;
  }
  input[type=text]:focus { border-color: var(--accent); }
  button {
    background: var(--accent); border: none; border-radius: 8px;
    color: #fff; cursor: pointer; font-size: 0.9rem; font-weight: 600;
    padding: 10px 20px; transition: opacity .2s;
  }
  button:hover { opacity: .85; }
  button:disabled { opacity: .45; cursor: default; }
  .badge {
    display: inline-block; border-radius: 5px; font-size: 0.7rem;
    font-weight: 700; letter-spacing: .05em; padding: 2px 7px;
    text-transform: uppercase; vertical-align: middle; margin-right: 6px;
  }
  .badge-mpd  { background: #7c3aed; }
  .badge-hls  { background: #0e7490; }
  .badge-mp4  { background: #065f46; }
  .badge-webm { background: #92400e; }
  .badge-iframe { background: #3b3f58; }
  .url-row {
    align-items: flex-start; background: var(--bg); border: 1px solid var(--border);
    border-radius: 8px; display: flex; gap: 8px; margin-top: 8px; padding: 10px 12px;
  }
  .url-text {
    flex: 1; font-family: monospace; font-size: 0.78rem;
    overflow-wrap: anywhere; color: var(--text); line-height: 1.5;
  }
  .copy-btn {
    background: var(--border); border-radius: 5px; border: none;
    color: var(--muted); cursor: pointer; flex-shrink: 0;
    font-size: 0.75rem; padding: 4px 9px; transition: background .2s;
  }
  .copy-btn:hover { background: var(--accent); color: #fff; }
  .section-title { color: var(--muted); font-size: 0.8rem; font-weight: 600;
                   letter-spacing: .06em; margin: 18px 0 4px; text-transform: uppercase; }
  .status-bar { font-size: 0.82rem; margin-top: 6px; }
  .ok    { color: var(--green); }
  .warn  { color: var(--yellow); }
  .err   { color: var(--red); }
  #spinner { display: none; color: var(--muted); font-size: 0.85rem; margin-top: 10px; }
  #spinner.active { display: block; }
  .protection-tag {
    background: #7f1d1d; border-radius: 5px; color: #fca5a5;
    display: inline-block; font-size: 0.75rem; margin: 2px 4px 2px 0;
    padding: 2px 8px;
  }
  #empty-msg { color: var(--muted); font-size: 0.9rem; margin-top: 8px; }
  .api-note { color: var(--muted); font-size: 0.78rem; margin-top: 10px; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  @media (max-width: 480px) {
    .input-row { flex-direction: column; }
    button { width: 100%; }
  }
</style>
</head>
<body>
<h1>⚡ Stream Resolver</h1>
<p class="sub">Extracts DASH / HLS / MP4 stream URLs from embed pages — one request, clean output.</p>

<div class="card">
  <div class="input-row">
    <input type="text" id="urlInput" placeholder="https://api.insertunit.ws/embed/imdb/tt0373074"
           onkeydown="if(event.key==='Enter')resolve()">
    <button id="resolveBtn" onclick="resolve()">Resolve</button>
  </div>
  <div id="spinner">⏳ Fetching…</div>
  <div id="apiBase" class="api-note"></div>
</div>

<div id="results"></div>

<script>
/* ---- configuration ----
   When served by --serve the API is on the same origin.
   When the HTML is opened as a local file (file://) the API must be
   running somewhere — default http://localhost:8787
   Override by appending  ?api=http://myserver:8787  to the page URL.
*/
(function(){
  const params = new URLSearchParams(location.search);
  const api = params.get('api') ||
    (location.protocol === 'file:' ? 'http://localhost:8787' : '');
  window._API = api;
  const note = document.getElementById('apiBase');
  if (api) note.innerHTML = `API: <a href="${api}/" target="_blank">${api}</a>`;
})();

function kindBadge(kind) {
  const map = {mpd:'MPD',hls:'HLS',mp4:'MP4',webm:'WebM',iframe:'iframe'};
  return `<span class="badge badge-${kind}">${map[kind]||kind}</span>`;
}

function copyText(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = '✓';
    setTimeout(() => btn.textContent = 'copy', 1200);
  });
}

function renderUrls(urls, kind) {
  return urls.map(u => `
    <div class="url-row">
      ${kindBadge(kind)}
      <span class="url-text">${escHtml(u)}</span>
      <button class="copy-btn" onclick="copyText(${JSON.stringify(u)}, this)">copy</button>
    </div>`).join('');
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

async function resolve() {
  const url = document.getElementById('urlInput').value.trim();
  if (!url) return;
  const btn = document.getElementById('resolveBtn');
  const spinner = document.getElementById('spinner');
  const results = document.getElementById('results');
  btn.disabled = true;
  spinner.className = 'active';
  results.innerHTML = '';

  try {
    const endpoint = window._API + '/resolve?url=' + encodeURIComponent(url);
    const resp = await fetch(endpoint);
    const data = await resp.json();
    renderResult(data);
  } catch(e) {
    results.innerHTML = `<div class="card err">✖ ${escHtml(String(e))}<br>
      Is the resolver running? Start it with: <code>python stream_resolver.py --serve</code></div>`;
  } finally {
    btn.disabled = false;
    spinner.className = '';
  }
}

function renderResult(data) {
  const el = document.getElementById('results');
  let html = '<div class="card">';

  // status line
  const statusClass = data.status === 'ok' ? 'ok' : data.status === 'blocked' ? 'warn' : 'err';
  html += `<div class="status-bar">
    Status: <span class="${statusClass}">${escHtml(data.status)}</span>
    &nbsp;·&nbsp; HTTP ${data.http_status}
    &nbsp;·&nbsp; <a href="${escHtml(data.final_url)}" target="_blank" rel="noopener">page ↗</a>
  </div>`;

  // protections
  if (data.protections && data.protections.blocked) {
    const sigs = Object.keys(data.protections.signals || {});
    html += '<div style="margin-top:8px">';
    sigs.forEach(s => { html += `<span class="protection-tag">⚠ ${escHtml(s)}</span>`; });
    html += '</div>';
  }

  // errors
  (data.errors || []).forEach(e => {
    html += `<div class="err" style="margin-top:6px;font-size:.82rem">✖ ${escHtml(e)}</div>`;
  });

  // streams
  const sections = [
    ['mpd',   'DASH Manifests (MPD)'],
    ['hls',   'HLS Master Playlists (M3U8)'],
    ['mp4',   'Direct MP4'],
    ['webm',  'Direct WebM'],
    ['iframe','Nested Embed / Player URLs'],
  ];

  let found = 0;
  sections.forEach(([key, label]) => {
    const urls = data[key] || [];
    if (!urls.length) return;
    found += urls.length;
    html += `<div class="section-title">${label}</div>`;
    html += renderUrls(urls, key);
  });

  if (!found) {
    html += '<div id="empty-msg">No stream URLs found in the page source.</div>';
  } else {
    html += `<div class="status-bar ok" style="margin-top:12px">✔ ${found} stream URL(s) found</div>`;
  }

  // copy-all button
  if (found) {
    const all = JSON.stringify(data.all_streams || [], null, 2);
    html += `<div style="margin-top:12px">
      <button class="copy-btn" style="font-size:.8rem;padding:6px 12px"
        onclick="copyText(${JSON.stringify(all)}, this)">Copy all as JSON</button>
    </div>`;
  }

  html += '</div>';
  el.innerHTML = html;
}
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# GitHub Actions helper  (writes to $GITHUB_OUTPUT)
# ---------------------------------------------------------------------------

def _write_github_output(data: Dict[str, Any]) -> None:
    import os
    gho = os.environ.get("GITHUB_OUTPUT", "")
    if not gho:
        return
    with open(gho, "a") as fh:
        fh.write(f"streams={json.dumps(data.get('all_streams', []))}\n")
        fh.write(f"mpd={json.dumps(data.get('mpd', []))}\n")
        fh.write(f"hls={json.dumps(data.get('hls', []))}\n")
        fh.write(f"mp4={json.dumps(data.get('mp4', []))}\n")
        fh.write(f"status={data.get('status', '')}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract top-level stream URLs from an embed/player page."
    )
    parser.add_argument("--url", default="", help="Embed/player URL to resolve.")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="Output machine-readable JSON.")
    parser.add_argument("--timeout", type=int, default=20, help="HTTP timeout (seconds).")
    parser.add_argument("--serve", action="store_true",
                        help="Run as a local HTTP API server.")
    parser.add_argument("--host", default="0.0.0.0", help="Bind host for --serve.")
    parser.add_argument("--port", type=int, default=8787, help="Bind port for --serve.")
    parser.add_argument("--build-html", action="store_true",
                        help="Print the self-contained HTML page to stdout and exit.")
    args = parser.parse_args(argv)

    if args.build_html:
        print(build_html())
        return 0

    if args.serve:
        serve(args.host, args.port, args.timeout)
        return 0

    if not args.url:
        parser.print_help()
        return 1

    data = resolve(args.url, timeout=args.timeout)
    print_result(data, as_json=args.as_json)
    _write_github_output(data)

    return 0 if data["status"] == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())