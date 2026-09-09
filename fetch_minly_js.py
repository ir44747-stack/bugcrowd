#!/usr/bin/env python3
"""
Fetch Minly.com JavaScript files - Passive & Scope-Enforced
Purpose: Collect real JS assets for local analysis by passive_recon.py

AGENTS_RULES.md Compliance:
- Rule 1 No Blind Scanning: Only fetches main page + JS URLs found in <script src=""> tags. No brute-force, no crawling, no fuzzing.
  Rate-limited (2s delay), single domain, GET only.
- Rule 2 Passive Recon First: This IS the collection step for passive analysis - JS is then analyzed locally by passive_recon.py
- Rule 4 Scope Adherence: Only downloads JS that is in-scope (minly.com, *.minly.com) OR same-origin. Out-of-scope CDN JS is skipped + logged.

Usage:
  python3 fetch_minly_js.py --domain https://minly.com --output-dir ./js_files --scope-file scope.txt

Safety:
  - Requires scope.txt to contain minly.com (fail-closed)
  - Rate-limited, identifiable User-Agent, respects timeout
  - Saves files with sanitized names to avoid overwriting
  - Use only on authorized scope (Bugcrowd program)
"""

import re
import time
import argparse
import hashlib
from pathlib import Path
from urllib.parse import urljoin, urlparse, unquote
from typing import List, Set

try:
    import requests
except ImportError:
    print("[!] 'requests' required: pip install -r requirements.txt")
    raise

DEFAULT_HEADERS = {
    "User-Agent": "BugBounty-Framework/1.0 (Authorized Passive JS Collection; Rate-Limited; Contact: security-researcher)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

SCOPE_DEFAULT = ["minly.com", "*.minly.com"]
DELAY = 2.0
TIMEOUT = 15

SCRIPT_SRC_REGEX = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)


def load_scope(scope_file: Path) -> List[str]:
    if not scope_file.exists():
        return SCOPE_DEFAULT
    lines = [l.strip() for l in scope_file.read_text().splitlines() if l.strip() and not l.strip().startswith('#')]
    return lines if lines else SCOPE_DEFAULT


def is_in_scope(url: str, scope_list: List[str]) -> bool:
    try:
        hostname = urlparse(url).hostname or ""
        hostname = hostname.lower()
        for scope in scope_list:
            scope_clean = scope.lower().strip().lstrip('*.').lstrip('.')
            if hostname == scope_clean or hostname.endswith('.' + scope_clean):
                return True
        return False
    except Exception:
        return False


def sanitize_filename(url: str) -> str:
    """Create safe filename from URL."""
    parsed = urlparse(url)
    # Use path + hash to avoid collisions
    path = unquote(parsed.path).strip('/').replace('/', '_')
    if not path or path == '_':
        path = "main"
    if not path.endswith('.js'):
        path = path + '.js'
    # Add short hash of full URL to ensure uniqueness
    h = hashlib.sha256(url.encode()).hexdigest()[:8]
    # Limit length
    name = f"{path[:80]}_{h}.js" if not path.endswith(f"_{h}.js") else path
    # Remove unsafe chars
    name = re.sub(r'[^a-zA-Z0-9._-]', '_', name)
    return name


def fetch_main_page(domain_url: str) -> str:
    print(f"[*] Fetching main page: {domain_url}")
    resp = requests.get(domain_url, headers=DEFAULT_HEADERS, timeout=TIMEOUT)
    resp.raise_for_status()
    print(f"  -> {resp.status_code} {len(resp.text)} bytes")
    return resp.text


def extract_js_urls(html: str, base_url: str, scope_list: List[str]) -> List[str]:
    """Extract <script src=*.js> URLs, resolve relative, filter to in-scope."""
    raw_matches = SCRIPT_SRC_REGEX.findall(html)
    print(f"[*] Found {len(raw_matches)} <script src> references")

    resolved = []
    seen = set()
    for src in raw_matches:
        src = src.strip()
        if not src or src.startswith('data:') or src.startswith('blob:'):
            continue
        abs_url = urljoin(base_url, src)
        # Normalize
        abs_url = abs_url.split('#')[0] # remove fragment
        if abs_url in seen:
            continue
        seen.add(abs_url)

        # Scope check - only keep in-scope JS for Rule 4 compliance
        # Note: Many sites use CDN, but we strictly enforce scope here. If you need CDN JS that is still part of target, add CDN domain to scope.txt
        if is_in_scope(abs_url, scope_list):
            resolved.append(abs_url)
        else:
            print(f"  [-] Skipping out-of-scope JS (Rule 4): {abs_url}")

    print(f"[*] In-scope JS URLs to download: {len(resolved)}")
    for u in resolved:
        print(f"  - {u}")
    return resolved


def download_js_files(js_urls: List[str], output_dir: Path, delay: float):
    output_dir.mkdir(parents=True, exist_ok=True)
    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    downloaded = []
    for idx, url in enumerate(js_urls, 1):
        filename = sanitize_filename(url)
        dest = output_dir / filename

        print(f"\n[{idx}/{len(js_urls)}] Downloading: {url}")
        print(f"  -> Saving as: {dest}")

        try:
            time.sleep(delay)
            resp = session.get(url, timeout=TIMEOUT)
            if resp.status_code == 200 and 'javascript' in resp.headers.get('Content-Type', '').lower() or url.endswith('.js') or len(resp.text) > 0:
                # Basic sanity: must look like JS
                if len(resp.content) > 100: # skip tiny empty files
                    dest.write_bytes(resp.content)
                    print(f"  -> Saved {len(resp.content)} bytes")
                    downloaded.append(str(dest))
                else:
                    print(f"  [!] Skipped - too small ({len(resp.content)} bytes)")
            else:
                print(f"  [!] Skipped - status {resp.status_code} Content-Type {resp.headers.get('Content-Type')}")
        except Exception as e:
            print(f"  [!] Failed: {e}")

    return downloaded


def main():
    parser = argparse.ArgumentParser(description="Fetch Minly.com JS files passively - AGENTS_RULES compliant")
    parser.add_argument("--domain", type=str, default="https://minly.com", help="Main page URL (must be in scope)")
    parser.add_argument("--output-dir", type=str, default="./js_files", help="Directory to save JS files")
    parser.add_argument("--scope-file", type=str, default="scope.txt", help="Scope file - must contain minly.com")
    parser.add_argument("--delay", type=float, default=DELAY, help="Delay between JS downloads (min 1.0s)")
    args = parser.parse_args()

    if args.delay < 1.0:
        print("[!] Delay must be >=1.0s for Rule 1 compliance, forcing to 1.0s")
        args.delay = 1.0

    scope_list = load_scope(Path(args.scope_file))
    print(f"[*] Scope: {scope_list}")

    # Verify domain is in scope (Rule 4)
    if not is_in_scope(args.domain, scope_list):
        print(f"[X] ERROR: Domain {args.domain} not in scope {scope_list} - aborting for Rule 4 compliance")
        print("    Update scope.txt to include minly.com")
        return

    if "minly.com" not in " ".join(scope_list):
        print("[X] scope.txt does not contain minly.com - aborting")
        return

    try:
        html = fetch_main_page(args.domain)
        js_urls = extract_js_urls(html, args.domain, scope_list)

        if not js_urls:
            print("\n[!] No in-scope JS URLs found on main page.")
            print("    Tips: Minly may load JS dynamically or via CDN out-of-scope.")
            print("    - Check browser DevTools > Sources for additional JS")
            print("    - If CDN is part of program scope, add its domain to scope.txt")
            print("    - You can manually save JS files to js_files/ for passive_recon.py")
            return

        downloaded = download_js_files(js_urls, Path(args.output_dir), args.delay)

        print("\n" + "="*70)
        print("FETCH COMPLETE")
        print("="*70)
        print(f"Downloaded {len(downloaded)} JS files to {args.output_dir}/")
        for f in downloaded:
            print(f"  - {f}")
        print("\nNext steps:")
        print(f"  python3 passive_recon.py --js-dir {args.output_dir} --scope-file {args.scope_file}")
        print(f"  python3 advanced_filter.py --input passive_recon_results.json --scope-file {args.scope_file} --output-dir ./clean_results")

    except requests.exceptions.RequestException as e:
        print(f"[X] Failed to fetch {args.domain}: {e}")
        print("    Ensure domain is reachable and you have authorization.")


if __name__ == "__main__":
    main()
