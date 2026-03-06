# Example 05: License Compliance Checking

## What This Tests

NitroGate's license scanner ensures new dependencies don't introduce incompatible licenses:

| Category | Examples | Default Action |
|---|---|---|
| **Permissive** | MIT, Apache-2.0, BSD-2-Clause, ISC | PASS |
| **Copyleft (warn)** | LGPL-2.1, MPL-2.0 | ADVISORY |
| **Copyleft (block)** | AGPL-3.0, GPL-3.0, GPL-2.0 | FAIL |
| **Unknown** | Unlicensed, custom | Configurable |

## How It Works

1. Scanner detects new dependencies added in the PR diff
2. Resolves license from package registry API:
   - npm: `https://registry.npmjs.org/{pkg}`
   - PyPI: `https://pypi.org/pypi/{pkg}/json`
3. Classifies license and reports violations

## Test Data

`package.json` adds dependencies with problematic licenses:
- `readline-sync` — ISC (permissive, PASS)
- `mysql` — GPL-2.0 (blocked by default policy)

## How to Run

```bash
cd /path/to/nitrogate
go test ./internal/scanner/ -run TestLicenseScanner -v
```

## Expected Findings

| Package | License | Verdict |
|---|---|---|
| readline-sync | ISC | PASS (permissive) |
| mysql | GPL-2.0 | FAIL (copyleft, denied in policy) |

## Policy Configuration

In `.nitrogate.json`:

```json
{
  "licenses": {
    "enabled": true,
    "denied": ["AGPL-3.0", "GPL-3.0", "GPL-2.0"],
    "warnOn": ["LGPL-2.1", "MPL-2.0"],
    "allowUnknown": false
  }
}
```

## Why This Matters

If your company ships a SaaS product:
- **AGPL-3.0** requires you to release your entire source code if users interact with it over a network
- **GPL-3.0** requires derivative works to be GPL-licensed
- NitroGate catches these **before merge**, not during a legal audit
