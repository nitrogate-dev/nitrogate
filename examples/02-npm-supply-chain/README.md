# Example 02: NPM Supply Chain Attack Detection

## What This Tests

NitroGate's NPM supply chain scanner protects against four categories of attacks:

| Check | What It Catches | Real-World Example |
|---|---|---|
| **Compromised packages** | Known-malicious packages | `event-stream` (2018), `ua-parser-js` (2021) |
| **Typosquatting** | Names similar to popular packages | `lodsah` instead of `lodash` |
| **Cooldown period** | Packages published very recently | New version published < 7 days ago |
| **Suspicious install scripts** | `preinstall`/`postinstall` running `curl`, `eval` | Crypto miners, data exfiltration |

## Test Data

`package.json` contains intentionally dangerous dependencies:
- `event-stream@3.3.6` — the exact compromised version from the 2018 attack
- `lodsah@4.17.21` — typosquatting `lodash`
- A package with a suspicious `postinstall` script

## How to Run

```bash
cd /path/to/nitrogate
go test ./internal/scanner/ -run TestNPMSupplyChain -v
```

## Expected Output

```
=== RUN   TestNPMSupplyChainScanner_CompromisedPackages
--- PASS: TestNPMSupplyChainScanner_CompromisedPackages (0.00s)
=== RUN   TestNPMSupplyChainScanner_Typosquatting
--- PASS: TestNPMSupplyChainScanner_Typosquatting (0.00s)
=== RUN   TestLevenshtein
--- PASS: TestLevenshtein (0.00s)
```

## Findings

| Finding | Severity | Detail |
|---|---|---|
| Compromised: event-stream | **CRITICAL** | Known compromised package — contained cryptocurrency-stealing malware |
| Typosquatting: lodsah | **HIGH** | Levenshtein distance 2 from `lodash` — possible typosquatting |
| Suspicious install script | **HIGH** | `postinstall` script contains `curl` command — possible data exfiltration |

## The Real-World Problem

In 2018, `event-stream` was taken over by an attacker who added a dependency (`flatmap-stream`) that stole Bitcoin wallet keys from Copay users. NitroGate maintains a list of 16+ known compromised packages and flags them instantly.

For typosquatting, attackers publish packages like `electorn` (instead of `electron`) or `cross-env` → `crossenv`. NitroGate checks Levenshtein distance against 60+ popular npm packages.
