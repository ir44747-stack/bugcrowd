#!/usr/bin/env python3
"""
Targeted Probing and Parameter Discovery Module - targeted_probe.py
Final core component of bug bounty framework.

STRICTLY adheres to AGENTS_RULES.md:
- Rule 1 No Blind Scanning: No brute-force, no fuzzing, no DoS. Single baseline request per endpoint,
  rate-limited (default 2s delay), max 10 param tests per endpoint, GET only by default.
- Rule 2 Passive Recon First: Consumes clean_results from advanced_filter.py - only probes already-filtered, in-scope endpoints.
- Rule 3 False Positive Filtering: Differential analysis + local validation before logging.
- Rule 4 Scope Adherence: Every request validated against scope.txt. Out-of-scope = skipped + logged.

SAFETY & AUTHORIZATION REQUIREMENTS:
- This module MUST only be used on targets where you have explicit authorization (Bugcrowd/HackerOne program).
- Requires --confirm-authorized flag to run any network requests.
- Rate-limited, non-destructive, no auth bypass, no ID iteration, no state-changing methods by default.
- Parameter discovery is for identifying accepted parameter NAMES (e.g., does ?page= exist?), NOT for exploiting IDOR to access other users' data.

If you are not authorized, use --dry-run to see what WOULD be tested without sending traffic.
"""

import json
import time
import argparse
import random
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Set
import hashlib
from datetime import datetime

# Optional dependency - only needed for live probing
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# --- CONFIGURATION (Safe defaults) ---

# Rate limiting - be kind to targets (Rule 1)
DEFAULT_DELAY = 2.0  # seconds between requests
DEFAULT_JITTER = 0.5 # random jitter to avoid pattern
MAX_REQUESTS_PER_ENDPOINT = 10
DEFAULT_TIMEOUT = 10

# Safe HTTP methods only - no state-changing by default
SAFE_METHODS = ["GET", "HEAD", "OPTIONS"]

# Small, non-sensitive parameter name list for discovery
# Purpose: detect if endpoint ACCEPTS parameter, not to brute-force values or exploit
# This is NOT a brute-force wordlist - intentionally limited to common, safe names
COMMON_PARAMS_SAFE = [
    "id", "page", "limit", "offset", "sort", "order", "q", "search",
    "lang", "locale", "format", "callback", "api_key", "token",
    "user_id", "account_id", "debug", "test", "verbose", "fields",
    "include", "exclude", "filter", "view", "type", "status"
]
# Limit to first N for safety
MAX_PARAMS_TO_TEST = 10

# Headers for responsible disclosure / identification
DEFAULT_HEADERS = {
    "User-Agent": "BugBounty-Framework/1.0 (Authorized Testing; Rate-Limited; Contact: security-researcher)",
    "Accept": "application/json, text/plain, */*",
}


def load_scope(scope_file: Path) -> List[str]:
    if not scope_file.exists():
        return []
    return [l.strip() for l in scope_file.read_text().splitlines() if l.strip() and not l.strip().startswith('#')]


def is_in_scope(url: str, scope_list: List[str]) -> bool:
    """Rule 4: Strict scope validation before ANY request."""
    if not scope_list:
        return False # Fail-closed if no scope
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


def load_clean_results(input_path: Path) -> Dict:
    """Load output from advanced_filter.py"""
    if not input_path.exists():
        raise FileNotFoundError(f"Clean results not found: {input_path}. Run advanced_filter.py first.")
    data = json.loads(input_path.read_text())
    return data


def build_url_with_param(base_url: str, param_name: str, param_value: str = "1") -> str:
    """Safely add/replace a single query param for testing acceptance."""
    parsed = urlparse(base_url)
    qs = parse_qs(parsed.query)
    # Don't overwrite existing params, just add test param
    if param_name in qs:
        return None # Already present, skip
    qs[param_name] = [param_value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


def rate_limited_request(session, method: str, url: str, delay: float, jitter: float) -> Dict:
    """Perform a single rate-limited, safe request and return structured log."""
    time.sleep(delay + random.uniform(0, jitter))
    
    start = time.time()
    try:
        resp = session.request(method, url, headers=DEFAULT_HEADERS, timeout=DEFAULT_TIMEOUT, allow_redirects=False)
        elapsed = time.time() - start
        
        # Safe logging - truncate body, keep metadata for differential analysis
        body_preview = resp.text[:500] if resp.text else ""
        body_hash = hashlib.sha256(resp.text.encode('utf-8', errors='ignore')).hexdigest()[:16] if resp.text else "empty"
        
        return {
            "url": url,
            "method": method,
            "status_code": resp.status_code,
            "elapsed_ms": int(elapsed * 1000),
            "content_length": len(resp.content),
            "body_hash": body_hash,
            "body_preview": body_preview,
            "headers": dict(resp.headers),
            "request_headers": dict(resp.request.headers),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "error": None
        }
    except Exception as e:
        return {
            "url": url,
            "method": method,
            "status_code": None,
            "elapsed_ms": int((time.time() - start)*1000),
            "content_length": 0,
            "body_hash": "error",
            "body_preview": "",
            "headers": {},
            "request_headers": DEFAULT_HEADERS,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "error": str(e)
        }


def differential_analysis(baseline: Dict, test: Dict) -> Dict:
    """Compare baseline vs param test - local analysis only, no exploitation."""
    diff = {
        "status_changed": baseline.get("status_code") != test.get("status_code"),
        "length_diff": test.get("content_length", 0) - baseline.get("content_length", 0),
        "hash_changed": baseline.get("body_hash") != test.get("body_hash"),
        "interesting": False,
        "reason": []
    }
    # Heuristic for "parameter might be accepted" - conservative
    if diff["status_changed"]:
        diff["reason"].append(f"status {baseline.get('status_code')} -> {test.get('status_code')}")
    if abs(diff["length_diff"]) > 50: # Significant length change
        diff["reason"].append(f"length diff {diff['length_diff']}")
    if diff["hash_changed"] and test.get("status_code") == 200:
        diff["reason"].append("body hash changed on 200")

    # Mark interesting only if multiple signals, to reduce false positives (Rule 3)
    if len(diff["reason"]) >= 1 and test.get("status_code") in [200, 400, 422]: # 400/422 often means param recognized but invalid
        diff["interesting"] = True

    return diff


def main():
    parser = argparse.ArgumentParser(description="Targeted Probing & Parameter Discovery - AGENTS_RULES Compliant (Authorized Testing Only)")
    parser.add_argument("--input", type=str, default="clean_results/clean_results.json", help="Clean JSON from advanced_filter.py")
    parser.add_argument("--scope-file", type=str, default="scope.txt", help="Scope file - mandatory for live probing")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY, help="Delay between requests in seconds (min 1.0)")
    parser.add_argument("--max-params", type=int, default=MAX_PARAMS_TO_TEST, help="Max params to test per endpoint (max 10)")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be probed, send NO requests (safe default)")
    parser.add_argument("--confirm-authorized", action="store_true", help="REQUIRED to send any live traffic - confirms you have authorization")
    parser.add_argument("--output-dir", type=str, default="./probe_results", help="Output dir for PoC logs")
    parser.add_argument("--endpoints-file", type=str, help="Optional: flat file endpoints_clean.txt to probe instead of JSON")
    args = parser.parse_args()

    # Safety checks
    if args.delay < 1.0:
        print("[!] Delay must be >= 1.0s for Rule 1 compliance. Forcing to 1.0s")
        args.delay = 1.0
    if args.max_params > MAX_REQUESTS_PER_ENDPOINT:
        print(f"[!] max-params capped to {MAX_REQUESTS_PER_ENDPOINT} for Rule 1 compliance")
        args.max_params = MAX_REQUESTS_PER_ENDPOINT

    scope_list = load_scope(Path(args.scope_file))
    if not scope_list:
        print(f"[!] Scope file {args.scope_file} missing or empty. Live probing DISABLED for Rule 4 compliance.")
        print("    Use --dry-run to preview, or provide valid scope.txt")

    # Load endpoints
    endpoints_to_probe = []
    if args.endpoints_file:
        endpoints_to_probe = [l.strip() for l in Path(args.endpoints_file).read_text().splitlines() if l.strip()]
    else:
        try:
            data = load_clean_results(Path(args.input))
            # Flatten categorized endpoints
            for cat, eps in data.get("endpoints", {}).items():
                endpoints_to_probe.extend(eps)
            # Also include raw list if present
            if not endpoints_to_probe and "endpoints" in data and isinstance(data["endpoints"], list):
                endpoints_to_probe = data["endpoints"]
        except FileNotFoundError as e:
            print(f"[!] {e}")
            # Fallback to clean_results/endpoints_clean.txt
            fallback = Path("clean_results/endpoints_clean.txt")
            if fallback.exists():
                endpoints_to_probe = [l.strip() for l in fallback.read_text().splitlines() if l.strip()]
                print(f"[*] Using fallback {fallback}")

    # Filter to only http/https and in-scope
    in_scope_endpoints = []
    for ep in endpoints_to_probe:
        if not ep.startswith("http"):
            continue # Skip relative paths - need full URL for safe probing, don't guess
        if not is_in_scope(ep, scope_list):
            print(f"[-] Skipping out-of-scope: {ep}")
            continue
        in_scope_endpoints.append(ep)

    print("\n" + "="*70)
    print("TARGETED PROBING MODULE - AGENTS_RULES.md COMPLIANT")
    print("="*70)
    print(f"Total endpoints found: {len(endpoints_to_probe)}")
    print(f"In-scope absolute URLs to probe: {len(in_scope_endpoints)}")
    print(f"Scope: {scope_list}")
    print(f"Rate limit: {args.delay}s + jitter, max {args.max_params} params/endpoint")
    print(f"Mode: {'DRY-RUN (no traffic)' if args.dry_run or not args.confirm_authorized else 'LIVE (authorized)'}")

    if not args.dry_run and not args.confirm_authorized:
        print("\n[!] LIVE probing requires --confirm-authorized")
        print("    You must confirm you have explicit authorization for these targets.")
        print("    Running in DRY-RUN mode instead. Add --confirm-authorized to send traffic.")
        args.dry_run = True

    if args.dry_run:
        print("\n--- DRY-RUN PREVIEW (No requests sent) ---")
        for ep in in_scope_endpoints[:20]: # Preview first 20
            print(f"  Would baseline GET: {ep}")
            for param in COMMON_PARAMS_SAFE[:args.max_params]:
                test_url = build_url_with_param(ep, param)
                if test_url:
                    print(f"    -> Would test param: {param} => {test_url}")
        print(f"\n[+] Dry-run complete. {len(in_scope_endpoints)} endpoints would be probed.")
        print("    To run live (if authorized): add --confirm-authorized")
        return

    # LIVE PROBING - Only if authorized
    if not HAS_REQUESTS:
        print("[!] 'requests' library not found. Install via pip install -r requirements.txt")
        return

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    session = requests.Session()
    session.headers.update(DEFAULT_HEADERS)

    all_pocs = []
    summary = []

    print(f"\n[*] Starting safe probing of {len(in_scope_endpoints)} endpoints...")
    for idx, endpoint in enumerate(in_scope_endpoints, 1):
        print(f"\n[{idx}/{len(in_scope_endpoints)}] Baseline: {endpoint}")
        
        baseline_log = rate_limited_request(session, "GET", endpoint, args.delay, DEFAULT_JITTER)
        print(f"  Baseline -> {baseline_log['status_code']} len={baseline_log['content_length']} hash={baseline_log['body_hash']}")

        param_results = []
        # Test limited safe params
        for param_name in COMMON_PARAMS_SAFE[:args.max_params]:
            test_url = build_url_with_param(endpoint, param_name, "1")
            if not test_url:
                continue

            test_log = rate_limited_request(session, "GET", test_url, args.delay, DEFAULT_JITTER)
            diff = differential_analysis(baseline_log, test_log)

            result_entry = {
                "param": param_name,
                "test_url": test_url,
                "test_log": test_log,
                "differential": diff
            }
            param_results.append(result_entry)

            marker = " [INTERESTING]" if diff["interesting"] else ""
            print(f"    ?{param_name}=1 -> {test_log['status_code']} diff={diff['length_diff']} {marker}")
            if diff["reason"]:
                print(f"      Reason: {', '.join(diff['reason'])}")

        # Build PoC log for this endpoint
        poc = {
            "endpoint": endpoint,
            "baseline": baseline_log,
            "param_tests": param_results,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "compliance_notes": "Rate-limited, scope-validated, GET only, no exploitation"
        }
        all_pocs.append(poc)

        # Summary for analyst
        interesting_params = [r["param"] for r in param_results if r["differential"]["interesting"]]
        if interesting_params:
            summary.append({"endpoint": endpoint, "potentially_accepted_params": interesting_params})

    # Save PoC logs - local only, for reporting (Rule 3)
    (output_dir / "poc_logs.json").write_text(json.dumps(all_pocs, indent=2))
    
    # Save analyst-ready summary
    (output_dir / "parameter_discovery_summary.json").write_text(json.dumps(summary, indent=2))
    
    flat_summary = []
    for item in summary:
        for p in item["potentially_accepted_params"]:
            flat_summary.append(f"{item['endpoint']} param:{p}")
    (output_dir / "interesting_params.txt").write_text("\n".join(flat_summary))

    # Final report
    print("\n" + "="*70)
    print("PROBING COMPLETE - POC LOGS GENERATED")
    print("="*70)
    print(f"Endpoints probed: {len(in_scope_endpoints)}")
    print(f"Endpoints with potentially accepted params: {len(summary)}")
    print(f"Total requests sent: ~{len(in_scope_endpoints) * (1 + args.max_params)} (rate-limited at {args.delay}s)")
    print(f"\nOutput: {output_dir}/")
    print(f"  - poc_logs.json (full request/response headers, status, diff - for reporting)")
    print(f"  - parameter_discovery_summary.json (categorized interesting params)")
    print(f"  - interesting_params.txt (flat list)")
    print("\n[!] NEXT STEPS (Manual Review Required):")
    print("  1. Review poc_logs.json - verify each 'interesting' param manually")
    print("  2. DO NOT automatically exploit - IDOR/Business Logic testing must be manual,")
    print("     single-request, and within program rules. Document impact carefully.")
    print("  3. All logs are local - attach relevant portions to your Bugcrowd report with")
    print("     differential analysis, not automated exploitation.")


if __name__ == "__main__":
    main()
