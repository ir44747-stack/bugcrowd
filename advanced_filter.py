#!/usr/bin/env python3
"""
Advanced Filtering and Processing Module
Interfaces with passive_recon.py output (passive_recon_results.json)

Strictly adheres to AGENTS_RULES.md:
- Rule 1: No Blind Scanning - This module makes ZERO network requests. Pure local processing.
- Rule 2: Passive Recon First - Processes already-collected passive data only.
- Rule 3: False Positive Filtering - Strict keyword blacklisting + validation before output.
- Rule 4: Scope Adherence - Validates every item against scope boundaries.

Input: passive_recon_results.json (from passive_recon.py)
Output: Clean, categorized, analyst-ready lists
"""

import json
import re
import argparse
from pathlib import Path
from urllib.parse import urlparse
from typing import List, Dict, Set, Tuple
from collections import defaultdict

# --- STRICT BLACKLISTING (Rule 3) ---

# Keywords that indicate false positives / low-value findings
# These are filtered LOCALLY before any human review
ENDPOINT_BLACKLIST_KEYWORDS = [
    # Analytics & tracking
    "google-analytics", "googletagmanager", "facebook", "doubleclick",
    "hotjar", "mixpanel", "segment.io", "intercom", "zendesk",
    # CDNs & static libs (not interesting for vuln analysis)
    "cdn.jsdelivr", "cdnjs.cloudflare", "unpkg.com", "bootstrap",
    "jquery", "lodash", "moment.js", "react.production",
    # Common false positives from JS parsing
    "w3.org", "schema.org", "example.com", "test.com",
    "localhost", "127.0.0.1", "0.0.0.0",
    # Data URIs & blobs
    "data:image", "data:text", "blob:",
    # Extensions that are static assets
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2", ".ttf", ".ico",
]

SUBDOMAIN_BLACKLIST_KEYWORDS = [
    "w3.org", "schema.org", "example.com",
    "github.com", "google.com", "facebook.com", # third-party mentions
    "s3.amazonaws.com", # generic AWS, not target-specific
]

# Regex patterns for high-confidence filtering
ENDPOINT_BLACKLIST_REGEX = [
    re.compile(r"^/static/", re.I),
    re.compile(r"^/assets/", re.I),
    re.compile(r"^/images?/", re.I),
    re.compile(r"\.(css|png|jpg|jpeg|gif|svg|woff2?|ico)(\?|$)", re.I),
]

# --- CATEGORIZATION PATTERNS ---

ENDPOINT_CATEGORIES = {
    "api": re.compile(r"/api/|/v[1-3]/|/rest/|/graphql", re.I),
    "auth": re.compile(r"/auth|/login|/logout|/signin|/signup|/oauth|/sso|/token", re.I),
    "admin": re.compile(r"/admin|/dashboard|/manage|/console", re.I),
    "upload": re.compile(r"/upload|/file|/import|/media", re.I),
    "user": re.compile(r"/user|/account|/profile|/settings", re.I),
    "payment": re.compile(r"/pay|/checkout|/billing|/invoice|/stripe", re.I),
    "debug": re.compile(r"/debug|/test|/dev|/staging|/internal", re.I),
    "graphql": re.compile(r"/graphql|/graphiql", re.I),
}

SUBDOMAIN_CATEGORIES = {
    "api": re.compile(r"^api\.|^rest\.|^graphql\.", re.I),
    "admin": re.compile(r"^admin\.|^dashboard\.|^manage\.|^console\.", re.I),
    "dev_staging": re.compile(r"^(dev|staging|test|qa|uat|beta)\.", re.I),
    "internal": re.compile(r"^(internal|corp|private|vpn)\.", re.I),
    "auth": re.compile(r"^(auth|sso|login|idp)\.", re.I),
    "cdn_assets": re.compile(r"^(cdn|assets|static|media|img)\.", re.I),
}


def load_results(json_path: Path) -> dict:
    """Load passive_recon.py JSON output."""
    if not json_path.exists():
        raise FileNotFoundError(f"Input file not found: {json_path}. Run passive_recon.py first.")
    data = json.loads(json_path.read_text())
    print(f"[*] Loaded {json_path}: {len(data.get('endpoints', []))} endpoints, {len(data.get('subdomains', []))} subdomains")
    return data


def load_scope(scope_file: Path = None, scope_from_json: List[str] = None) -> List[str]:
    """Load scope list from file or from JSON results."""
    if scope_file and scope_file.exists():
        scope = [l.strip() for l in scope_file.read_text().splitlines() if l.strip() and not l.strip().startswith('#')]
        print(f"[*] Scope loaded from {scope_file}: {scope}")
        return scope
    if scope_from_json:
        print(f"[*] Scope loaded from JSON: {scope_from_json}")
        return scope_from_json
    return []


def is_in_scope(url_or_domain: str, scope_list: List[str]) -> bool:
    """Rule 4: Scope Adherence - strict boundary validation."""
    if not scope_list:
        return True # If no scope defined, allow all (but warn)
    try:
        if "://" in url_or_domain:
            hostname = urlparse(url_or_domain).hostname or url_or_domain
        else:
            hostname = url_or_domain.split('/')[0].split('?')[0]
        hostname = hostname.lower().strip()

        for scope in scope_list:
            scope_clean = scope.lower().strip().lstrip('*.').lstrip('.')
            if hostname == scope_clean or hostname.endswith('.' + scope_clean):
                return True
        return False
    except Exception:
        return False


def is_blacklisted(value: str, blacklist_keywords: List[str], blacklist_regex: List[re.Pattern] = None) -> Tuple[bool, str]:
    """Rule 3: Strict keyword blacklisting with reason."""
    v_lower = value.lower()
    for kw in blacklist_keywords:
        if kw.lower() in v_lower:
            return True, f"keyword:{kw}"
    if blacklist_regex:
        for rx in blacklist_regex:
            if rx.search(value):
                return True, f"regex:{rx.pattern}"
    return False, ""


def categorize_endpoint(endpoint: str) -> str:
    """Categorize endpoint by interest level."""
    for cat, pattern in ENDPOINT_CATEGORIES.items():
        if pattern.search(endpoint):
            return cat
    return "other"


def categorize_subdomain(subdomain: str) -> str:
    """Categorize subdomain."""
    for cat, pattern in SUBDOMAIN_CATEGORIES.items():
        if pattern.search(subdomain):
            return cat
    return "other"


def process_endpoints(endpoints: List[str], scope_list: List[str]) -> Dict[str, List[str]]:
    """Parse, filter, validate, and categorize endpoints."""
    print(f"\n[*] Processing {len(endpoints)} raw endpoints...")
    
    filtered_out = []
    in_scope = []
    
    for ep in endpoints:
        # Rule 4: Scope validation
        if ep.startswith("http"):
            if not is_in_scope(ep, scope_list):
                filtered_out.append((ep, "out-of-scope"))
                continue
        
        # Rule 3: Strict blacklisting
        blacklisted, reason = is_blacklisted(ep, ENDPOINT_BLACKLIST_KEYWORDS, ENDPOINT_BLACKLIST_REGEX)
        if blacklisted:
            filtered_out.append((ep, reason))
            continue
        
        # Additional local sanity checks
        if len(ep) < 4 or len(ep) > 300:
            filtered_out.append((ep, "length-anomaly"))
            continue
            
        in_scope.append(ep)

    # Categorize clean list
    categorized = defaultdict(list)
    seen = set()
    for ep in in_scope:
        if ep in seen:
            continue
        seen.add(ep)
        cat = categorize_endpoint(ep)
        categorized[cat].append(ep)
    
    # Sort each category
    for cat in categorized:
        categorized[cat] = sorted(set(categorized[cat]))

    print(f"  -> Kept {len(in_scope)} / {len(endpoints)} (filtered {len(filtered_out)})")
    return dict(categorized), filtered_out


def process_subdomains(subdomains: List[str], scope_list: List[str]) -> Tuple[Dict[str, List[str]], List[Tuple[str, str]]]:
    """Parse, filter, validate, and categorize subdomains."""
    print(f"\n[*] Processing {len(subdomains)} raw subdomains...")
    
    filtered_out = []
    in_scope = []

    for sd in subdomains:
        sd = sd.lower().strip().strip('.')

        # Rule 4: Scope
        if not is_in_scope(sd, scope_list):
            filtered_out.append((sd, "out-of-scope"))
            continue

        # Rule 3: Blacklist
        blacklisted, reason = is_blacklisted(sd, SUBDOMAIN_BLACKLIST_KEYWORDS)
        if blacklisted:
            filtered_out.append((sd, reason))
            continue

        # Basic FQDN validation
        if "." not in sd or len(sd) < 4:
            filtered_out.append((sd, "invalid-fqdn"))
            continue

        in_scope.append(sd)

    categorized = defaultdict(list)
    seen = set()
    for sd in in_scope:
        if sd in seen:
            continue
        seen.add(sd)
        cat = categorize_subdomain(sd)
        categorized[cat].append(sd)

    for cat in categorized:
        categorized[cat] = sorted(set(categorized[cat]))

    print(f"  -> Kept {len(in_scope)} / {len(subdomains)} (filtered {len(filtered_out)})")
    return dict(categorized), filtered_out


def main():
    parser = argparse.ArgumentParser(description="Advanced Filtering Module - AGENTS_RULES.md Compliant")
    parser.add_argument("--input", type=str, default="passive_recon_results.json", help="JSON from passive_recon.py")
    parser.add_argument("--scope-file", type=str, default="scope.txt", help="Scope file for boundary validation")
    parser.add_argument("--output-dir", type=str, default="./clean_results", help="Output directory for clean lists")
    args = parser.parse_args()

    input_path = Path(args.input)
    scope_file = Path(args.scope_file) if args.scope_file else None
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load
    data = load_results(input_path)
    scope_list = load_scope(scope_file, data.get("scope", []))
    
    if not scope_list:
        print("[!] WARNING: No scope defined - all findings will be treated as in-scope. Provide scope.txt for Rule 4 compliance.")

    # Process
    endpoints = data.get("endpoints", [])
    subdomains = data.get("subdomains", [])

    cat_endpoints, filtered_eps = process_endpoints(endpoints, scope_list)
    cat_subdomains, filtered_subs = process_subdomains(subdomains, scope_list)

    # Prepare final clean output
    clean_output = {
        "metadata": {
            "input_file": str(input_path),
            "scope": scope_list,
            "total_raw_endpoints": len(endpoints),
            "total_raw_subdomains": len(subdomains),
            "compliance": "AGENTS_RULES.md - No scanning, filtered locally, scope validated"
        },
        "endpoints": cat_endpoints,
        "subdomains": cat_subdomains,
        "stats": {
            "clean_endpoints": sum(len(v) for v in cat_endpoints.values()),
            "clean_subdomains": sum(len(v) for v in cat_subdomains.values()),
            "filtered_endpoints": len(filtered_eps),
            "filtered_subdomains": len(filtered_subs),
        }
    }

    # Save categorized JSON
    (output_dir / "clean_results.json").write_text(json.dumps(clean_output, indent=2))
    
    # Save flat, analyst-ready lists
    all_clean_eps = []
    for cat_list in cat_endpoints.values():
        all_clean_eps.extend(cat_list)
    
    all_clean_subs = []
    for cat_list in cat_subdomains.values():
        all_clean_subs.extend(cat_list)

    (output_dir / "endpoints_clean.txt").write_text("\n".join(sorted(set(all_clean_eps))))
    (output_dir / "subdomains_clean.txt").write_text("\n".join(sorted(set(all_clean_subs))))

    # Save categorized breakdowns
    for cat, items in cat_endpoints.items():
        (output_dir / f"endpoints_{cat}.txt").write_text("\n".join(items))
    
    for cat, items in cat_subdomains.items():
        (output_dir / f"subdomains_{cat}.txt").write_text("\n".join(items))

    # Save filtered log for audit
    filtered_log = {
        "filtered_endpoints": [{"value": v, "reason": r} for v, r in filtered_eps],
        "filtered_subdomains": [{"value": v, "reason": r} for v, r in filtered_subs],
    }
    (output_dir / "filtered_out_audit.json").write_text(json.dumps(filtered_log, indent=2))

    # Console summary
    print("\n" + "="*60)
    print("CLEAN RESULTS READY FOR ANALYSIS")
    print("="*60)
    print(f"Endpoints (clean): {clean_output['stats']['clean_endpoints']} in {len(cat_endpoints)} categories")
    for cat, items in cat_endpoints.items():
        print(f"  - {cat}: {len(items)}")
    
    print(f"\nSubdomains (clean): {clean_output['stats']['clean_subdomains']} in {len(cat_subdomains)} categories")
    for cat, items in cat_subdomains.items():
        print(f"  - {cat}: {len(items)}")

    print(f"\nFiltered out: {len(filtered_eps)} endpoints, {len(filtered_subs)} subdomains (see filtered_out_audit.json)")
    print(f"\nOutput directory: {output_dir}/")
    print(f"  - clean_results.json (full categorized)")
    print(f"  - endpoints_clean.txt (flat list)")
    print(f"  - subdomains_clean.txt (flat list)")
    print(f"  - endpoints_<category>.txt / subdomains_<category>.txt")
    print(f"  - filtered_out_audit.json (audit trail for Rule 3)")


if __name__ == "__main__":
    main()
