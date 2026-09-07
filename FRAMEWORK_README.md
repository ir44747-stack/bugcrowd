# Bug Bounty Framework - End-to-End (AGENTS_RULES.md Compliant)

Professional, modular framework for authorized bug bounty testing. Strictly passive-first, rate-limited, scope-enforced.

## Architecture

```
Stage 1: passive_recon.py
  Input:  ./js_files (locally collected JS)
  Output: passive_recon_results.json
  Rules:  No scanning, local analysis only, CT via 3rd party

Stage 2: advanced_filter.py
  Input:  passive_recon_results.json + scope.txt
  Output: clean_results/ (clean_results.json, endpoints_clean.txt, subdomains_clean.txt, categorized files)
  Rules:  Strict blacklist, scope validation, deduplication

Stage 3: targeted_probe.py (FINAL)
  Input:  clean_results/ + scope.txt
  Output: probe_results/ (poc_logs.json, parameter_discovery_summary.json)
  Rules:  Rate-limited GET only, max 10 params/endpoint, --confirm-authorized required, local PoC logs
```

## Files

- `AGENTS_RULES.md` - Core operational rules (mandatory)
- `passive_recon.py` - Stage 1 passive recon
- `advanced_filter.py` - Stage 2 filtering & categorization
- `targeted_probe.py` - Stage 3 safe probing & param discovery
- `requirements.txt` - Dependencies
- `scope.txt` - Scope allow-list (Rule 4)
- `probe_config.json` - Safe defaults for probing

## Setup

```bash
pip install -r requirements.txt
mkdir -p js_files clean_results probe_results

# 1. Edit scope.txt with your ACTUAL program scope from Bugcrowd/HackerOne
cat scope.txt

# 2. Collect JS files MANUALLY (no auto-download in framework to stay passive)
# Example: Save JS files from your browser devtools or via manual curl with permission
# cp ~/Downloads/*.js js_files/
```

## Execution - End-to-End

### Stage 1: Passive Recon
```bash
python3 passive_recon.py --js-dir ./js_files --scope-file scope.txt
# Optional: include passive CT (no target contact)
python3 passive_recon.py --js-dir ./js_files --scope-file scope.txt --domain example.com --use-ct
# Output: passive_recon_results.json
```

### Stage 2: Advanced Filtering
```bash
python3 advanced_filter.py --input passive_recon_results.json --scope-file scope.txt --output-dir ./clean_results
# Output: clean_results/endpoints_clean.txt, subdomains_clean.txt, clean_results.json
```

### Stage 3: Targeted Probing (AUTHORIZED ONLY)

**Dry-run first (no traffic):**
```bash
python3 targeted_probe.py --input clean_results/clean_results.json --scope-file scope.txt --dry-run
```

**Live probing (requires authorization):**
```bash
# Must have scope.txt and explicit confirmation
python3 targeted_probe.py --input clean_results/clean_results.json --scope-file scope.txt --delay 2.0 --max-params 10 --confirm-authorized

# Or using flat list
python3 targeted_probe.py --endpoints-file clean_results/endpoints_clean.txt --scope-file scope.txt --confirm-authorized --output-dir ./probe_results
```

**What it does safely:**
- 1 baseline GET per in-scope absolute URL
- Tests up to 10 common param names (e.g., ?page=1, ?id=1) with rate-limit 2s + jitter
- Records: status, content-length, body hash, headers, timestamp, differential analysis
- NO brute-force, NO ID iteration, NO POST/DELETE, NO auth bypass
- Generates local PoC logs for reporting: `probe_results/poc_logs.json`

## Configuration Requirements

`probe_config.json` enforces safety:
- `delay_seconds`: >=1.0 (default 2.0) - Rule 1
- `max_params_to_test`: <=10 - Rule 1
- `allowed_methods`: GET, HEAD, OPTIONS only
- `require_scope`: true - Rule 4 fail-closed
- `require_confirm_authorized`: true

Edit only to INCREASE delays, never decrease.

## PoC Log Generator

`targeted_probe.py` creates for each endpoint:
```json
{
  "endpoint": "https://api.example.com/v1/users",
  "baseline": {"status_code": 200, "content_length": 1234, "body_hash": "abc...", "headers": {...}},
  "param_tests": [
    {
      "param": "page",
      "test_url": "https://api.example.com/v1/users?page=1",
      "test_log": {...},
      "differential": {"status_changed": false, "length_diff": 20, "interesting": true, "reason": ["length diff 20"]}
    }
  ]
}
```

Use this for Bugcrowd reports - shows differential analysis, not exploitation.

## Commit to GitHub

```bash
git add AGENTS_RULES.md passive_recon.py advanced_filter.py targeted_probe.py requirements.txt scope.txt probe_config.json FRAMEWORK_README.md
git commit -m "Add end-to-end bug bounty framework v3: passive recon + advanced filter + targeted probe (AGENTS_RULES compliant)"
git push
```

## Compliance Checklist

- [ ] scope.txt updated with official program scope
- [ ] All JS files collected manually, not via framework auto-scanner
- [ ] Stage 1 & 2 run first, Stage 3 only on clean_results
- [ ] --dry-run reviewed before live
- [ ] --confirm-authorized only when you have explicit authorization
- [ ] Rate limits respected (>=1s, default 2s)
- [ ] PoC logs reviewed manually - no auto-exploitation for IDOR/Business Logic

## Legal / Ethical

This framework is for authorized testing only. Unauthorized testing violates Bugcrowd/HackerOne rules and law. Always stay in scope, rate-limit, and report responsibly.
