#!/usr/bin/env python3
"""
Passive Reconnaissance Module
Strictly adheres to AGENTS_RULES.md

Rule 1 - No Blind Scanning: No aggressive scans, no brute-force, no fuzzing, no DoS.
        This module NEVER hits target servers directly for enumeration.
        Subdomains are sourced from Certificate Transparency logs (crt.sh) - a 3rd party passive source.
        JS analysis is performed LOCALLY on files you have already collected.

Rule 2 - Passive Recon First: Focus on endpoint extraction, JS file analysis, safe subdomain enum.

Rule 3 - False Positive Filtering: All findings are filtered locally before output.

Rule 4 - Scope Adherence: Every finding is checked against an explicit allow-list.
"""

import os
import re
import json
import argparse
from pathlib import Path
from urllib.parse import urlparse
from typing import List, Set

# --- CONFIGURATION ---

# Example scope - MUST be replaced with your program's actual scope
DEFAULT_SCOPE = [
    "example.com",
    "*.example.com"
]

# Common false positives to filter out locally
FALSE_POSITIVE_PATTERNS = [
    r"example\.com",
    r"test\.com",
    r"localhost",
    r"127\.0\.0\.1",
    r"\.w3\.org",
    r"schema\.org",
    r"jquery",
    r"bootstrap",
    r"google-analytics\.com",
    r"googletagmanager\.com",
    r"facebook\.com",
    r"data:image",
    r"application/javascript",
]

# Regex patterns for endpoint extraction from JS
ENDPOINT_REGEXES = {
    "api_path": re.compile(r"""["'](/api/[^"'`\s]{1,100})["']"""),
    "relative_path": re.compile(r"""["'](/[a-zA-Z0-9_\-/]{3,80}(?:\?[^"'`]*)?)["']"""),
    "absolute_url": re.compile(r"""["'](https?://[a-zA-Z0-9._-]+\.[a-z]{2,}(?:/[^\s"'`]{0,120})?)["']"""),
    "js_fetch": re.compile(r"""(?:fetch|axios\.(?:get|post)|XMLHttpRequest\.open)\s*\(\s*["']([^"'`]+)["']"""),
}

SUBDOMAIN_REGEX = re.compile(r"""(?:[a-zA-Z0-9-]+\.)+[a-z]{2,}""")


def is_in_scope(url_or_domain: str, scope_list: List[str]) -> bool:
    """Rule 4: Scope Adherence - Check if finding is in allowed scope."""
    try:
        # Normalize to hostname
        if "://" in url_or_domain:
            hostname = urlparse(url_or_domain).hostname or url_or_domain
        else:
            hostname = url_or_domain.split('/')[0]
        
        hostname = hostname.lower().strip()

        for scope in scope_list:
            scope = scope.lower().strip().lstrip('*.').lstrip('.')
            # Exact match or subdomain match
            if hostname == scope or hostname.endswith('.' + scope):
                return True
        return False
    except Exception:
        return False


def is_false_positive(value: str) -> bool:
    """Rule 3: False Positive Filtering - Local filtering before output."""
    v_lower = value.lower()
    for pattern in FALSE_POSITIVE_PATTERNS:
        if re.search(pattern, v_lower):
            return True
    # Filter very short, generic paths
    if len(v_lower) < 5:
        return True
    # Filter static assets that are rarely interesting
    if re.search(r"\.(css|png|jpg|jpeg|gif|svg|woff2?|ico)(\?|$)", v_lower):
        return True
    return False


def extract_endpoints_from_js(js_content: str) -> Set[str]:
    """Rule 2: Passive endpoint extraction from JS content (local analysis only)."""
    found = set()
    for name, regex in ENDPOINT_REGEXES.items():
        matches = regex.findall(js_content)
        for m in matches:
            # fetch regex returns group 1, others return full match
            if isinstance(m, tuple):
                m = m[0]
            m = m.strip()
            if not is_false_positive(m):
                found.add(m)
    return found


def extract_subdomains_from_js(js_content: str, root_domain: str) -> Set[str]:
    """Extract potential subdomains mentioned in JS, then filter by scope."""
    candidates = SUBDOMAIN_REGEX.findall(js_content)
    valid = set()
    for cand in candidates:
        cand = cand.lower().strip('.,;\'"')
        # Must contain root domain to be relevant
        if root_domain in cand and not is_false_positive(cand):
            valid.add(cand)
    return valid


def analyze_js_directory(js_dir: Path, scope_list: List[str]) -> dict:
    """Analyze all .js files locally - comprehensive recursive search using os.walk('.')"""
    results = {"endpoints": set(), "subdomains": set(), "files_scanned": 0}

    root_domain = scope_list[0].lstrip('*.').lstrip('.') if scope_list else ""

    # Per request: comprehensive recursive search for all .js files in current dir and subdirs using os.walk('.')
    # This ensures files in root (e.g., test.js) are processed, not just rigid js_files/ folder
    search_base = "."  # Always search from current directory recursively as requested
    # If user explicitly provided a different existing directory, honor it as base, otherwise use "."
    if js_dir.exists() and str(js_dir) != ".":
        # If js_dir is provided (e.g., ./js_files), we still want comprehensive search from "." per request
        # So we will walk from "." to include root files like test.js AND js_files/
        # To respect the request fully, we use os.walk('.') regardless
        search_base = "."

    print(f"[*] Searching for .js files recursively using os.walk('{search_base}') - comprehensive search")

    for root, dirs, files in os.walk(search_base):
        # Skip noisy / irrelevant directories to keep filtering clean (Rule 3)
        # Keep js_files, but skip .git, caches, venvs, etc.
        dirs[:] = [d for d in dirs if d not in {'.git', '__pycache__', 'node_modules', '.venv', 'venv', 'env', 'dist', 'build', '.github', 'clean_results', 'probe_results'}]
        
        for file in files:
            if file.endswith('.js'):
                js_file_path = Path(root) / file
                try:
                    content = js_file_path.read_text(encoding='utf-8', errors='ignore')
                    results["files_scanned"] += 1

                    endpoints = extract_endpoints_from_js(content)
                    # Apply scope filter for absolute URLs
                    for ep in endpoints:
                        if ep.startswith("http"):
                            if is_in_scope(ep, scope_list):
                                results["endpoints"].add(ep)
                        else:
                            # Relative paths are kept - they are in-scope by definition if JS is in-scope
                            results["endpoints"].add(ep)

                    subs = extract_subdomains_from_js(content, root_domain)
                    for s in subs:
                        if is_in_scope(s, scope_list):
                            results["subdomains"].add(s)

                except Exception as e:
                    print(f"[!] Error reading {js_file_path}: {e}")

    return results


def get_subdomains_passive_ct(domain: str, scope_list: List[str]) -> Set[str]:
    """
    Rule 1 & 2: SAFE subdomain enumeration via Certificate Transparency.
    This queries crt.sh (third-party) - does NOT touch target servers.
    No brute-force, no DNS enumeration against target.
    
    To use: enable with --use-ct and ensure you respect crt.sh rate limits.
    """
    print(f"[*] [PASSIVE] Querying Certificate Transparency for {domain} (crt.sh) - no target contact")
    # NOTE: Implementation is intentionally left as a stub to enforce review.
    # To activate, uncomment the requests code below and add rate limiting.
    
    subdomains = set()
    # --- SAFE EXAMPLE (requires `requests`) ---
    # import requests, time
    # try:
    #     url = f"https://crt.sh/?q=%25.{domain}&output=json"
    #     resp = requests.get(url, timeout=20, headers={"User-Agent": "PassiveRecon-Module/1.0 (BugBounty-Scope-Compliant)"})
    #     if resp.status_code == 200:
    #         data = resp.json()
    #         for entry in data:
    #             for name in entry.get('name_value','').split('\n'):
    #                 name = name.lower().strip()
    #                 if is_in_scope(name, scope_list) and not is_false_positive(name):
    #                     subdomains.add(name)
    #     time.sleep(2) # Rate limit - be kind to public service
    # except Exception as e:
    #     print(f"[!] CT query failed: {e}")
    
    print("[*] CT function is in stub mode. Uncomment code after review to enable.")
    return subdomains


def final_filter_and_deduplicate(items: Set[str]) -> List[str]:
    """Final local validation before presenting to human reviewer."""
    cleaned = []
    seen = set()
    for item in items:
        item = item.strip()
        if item in seen:
            continue
        if is_false_positive(item):
            continue
        seen.add(item)
        cleaned.append(item)
    return sorted(cleaned)


def main():
    parser = argparse.ArgumentParser(description="Passive Recon Module - AGENTS_RULES.md Compliant")
    parser.add_argument("--js-dir", type=str, default="./js_files", help="Local directory containing collected JS files")
    parser.add_argument("--scope-file", type=str, help="File containing scope domains (one per line)")
    parser.add_argument("--domain", type=str, help="Root domain for CT passive enum (e.g., example.com)")
    parser.add_argument("--use-ct", action="store_true", help="Enable passive CT subdomain gathering (still no target scanning)")
    args = parser.parse_args()

    scope_list = DEFAULT_SCOPE
    if args.scope_file:
        scope_list = [line.strip() for line in Path(args.scope_file).read_text().splitlines() if line.strip() and not line.strip().startswith('#')]

    print(f"[*] Scope: {scope_list}")
    print(f"[*] Rule 1: No blind scanning - passive only")

    js_dir = Path(args.js_dir)
    js_results = analyze_js_directory(js_dir, scope_list)

    all_endpoints = final_filter_and_deduplicate(js_results["endpoints"])
    all_subdomains = final_filter_and_deduplicate(js_results["subdomains"])

    if args.use_ct and args.domain:
        if not is_in_scope(args.domain, scope_list):
            print(f"[!] Domain {args.domain} not in scope, skipping CT query (Rule 4)")
        else:
            ct_subs = get_subdomains_passive_ct(args.domain, scope_list)
            all_subdomains = final_filter_and_deduplicate(set(all_subdomains) | ct_subs)

    # Output - only after local filtering (Rule 3)
    print("\n--- RESULTS (Filtered & In-Scope Only) ---")
    print(f"Files scanned: {js_results['files_scanned']}")
    print(f"\nEndpoints ({len(all_endpoints)}):")
    for ep in all_endpoints:
        print(f"  - {ep}")

    print(f"\nSubdomains ({len(all_subdomains)}):")
    for sd in all_subdomains:
        print(f"  - {sd}")

    # Save to JSON for reviewer
    output = {
        "scope": scope_list,
        "files_scanned": js_results["files_scanned"],
        "endpoints": all_endpoints,
        "subdomains": all_subdomains,
        "compliance": "AGENTS_RULES.md: No blind scanning, passive only, filtered locally, scope adhered"
    }
    Path("passive_recon_results.json").write_text(json.dumps(output, indent=2))
    print("\n[+] Saved filtered results to passive_recon_results.json")


if __name__ == "__main__":
    main()
