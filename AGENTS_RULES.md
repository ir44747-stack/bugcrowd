# AGENTS RULES - Operational Guidelines

This document defines the core operational rules for all automated agents and security testing workflows in this repository.

## Rule 1: No Blind Scanning
Strictly avoid aggressive or noisy general scans that stress target servers. All testing must be rate-limited, targeted, and non-disruptive. Do not run large-scale brute-force, fuzzing, or DoS-style scans.

## Rule 2: Passive Recon First
Focus strictly on endpoint extraction, JS file analysis, and safe subdomain enumeration. Prioritize passive information gathering methods before any active interaction with targets.

## Rule 3: False Positive Filtering
Filter out and eliminate false positives locally before presenting any output to the human reviewer. All findings must be validated and de-duplicated to ensure high signal quality.

## Rule 4: Scope Adherence
Never exceed the defined scope of any given target program. Always verify the current scope from the official program page and strictly remain within authorized assets, domains, and testing methods.

---
*These rules are mandatory for all agents operating under this repository.*
