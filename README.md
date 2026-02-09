# cookie-check

[![npm version](https://img.shields.io/npm/v/@lxgicstudios/cookie-check.svg)](https://www.npmjs.com/package/@lxgicstudios/cookie-check)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Fetch any URL and audit all Set-Cookie headers for security issues. Checks HttpOnly, Secure, SameSite, Path, and Expires flags. Grades each cookie from A to F with actionable recommendations.

## Install

```bash
# Run directly with npx
npx @lxgicstudios/cookie-check https://example.com

# Or install globally
npm install -g @lxgicstudios/cookie-check
```

## Usage

```bash
# Audit cookies on any site
cookie-check https://example.com

# Verbose output with all attributes
cookie-check https://example.com --verbose

# CI mode with minimum grade requirement
cookie-check https://example.com --ci --min-grade B

# JSON output for pipelines
cookie-check https://example.com --json

# Add custom headers (auth tokens, etc.)
cookie-check https://example.com --header "Authorization: Bearer abc123"
```

## Features

- **Zero dependencies** - uses only built-in Node.js modules (https/http)
- Grades each cookie from A (secure) to F (dangerous)
- Checks all critical security flags: HttpOnly, Secure, SameSite
- Validates cookie prefix rules (`__Secure-` and `__Host-`)
- Detects missing expiry, overly long lifetimes, and oversized values
- Follows redirects by default (configurable)
- CI mode with configurable minimum grade threshold
- JSON output for pipeline integration
- Custom headers for authenticated endpoints

## Options

| Option | Description |
|--------|-------------|
| `--help` | Show help message |
| `--json` | Output results as JSON |
| `--ci` | Exit with code 1 if any cookie grades below threshold |
| `--min-grade <grade>` | Minimum acceptable grade, A-F (default: C) |
| `--follow-redirects` | Follow HTTP redirects (default: true) |
| `--no-redirects` | Don't follow redirects |
| `--timeout <ms>` | Request timeout in milliseconds (default: 10000) |
| `--header <h>` | Add custom header as "Name: Value" (repeatable) |
| `--verbose` | Show all cookie attributes |

## Cookie Grading

Each cookie gets a score from 0-100, then mapped to a letter grade:

| Grade | Score | What it means |
|-------|-------|--------------|
| A | 90-100 | Solid security flags. You're doing it right. |
| B | 75-89 | Minor issues. Good but could be better. |
| C | 60-74 | Missing some important flags. Fix these. |
| D | 40-59 | Significant security gaps. Needs attention. |
| F | 0-39 | Wide open. Fix immediately. |

## What Gets Checked

- **HttpOnly** - prevents JavaScript from reading the cookie (XSS protection)
- **Secure** - restricts cookie to HTTPS connections only
- **SameSite** - controls cross-site request behavior (CSRF protection)
- **Path** - checks if cookie is scoped appropriately
- **Expires/Max-Age** - validates cookie lifetime
- **Cookie prefixes** - validates `__Secure-` and `__Host-` prefix requirements
- **Value size** - flags cookies exceeding 4096 bytes

## License

MIT - [LXGIC Studios](https://github.com/lxgicstudios)
