# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue.**

Report security vulnerabilities privately to:

**salamanedal@gmail.com**

You will receive a response within 48 hours. If the issue is
confirmed, a fix will be released as soon as possible.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ |

## Known Security Protections

- **Duplicate key detection** — Prevents YAML merge-based privilege escalation
- **Alias depth limiting** — Prevents anchor bomb DoS attacks (default: 10 hops)
- **Prototype pollution guard** — Blocks `__proto__`, `constructor`, `prototype` keys
- **Node limit** — Prevents memory exhaustion (default: 10,000 nodes)
- **Expansion guard** — Counts total nested elements to detect Billion Laughs attacks (default: 100,000 elements)
- **Alias expansion limit** — Limits total alias resolutions (default: 100)
- **Recursion guard** — Limits YAML parser recursion depth (50 max)
- **Input size limit** — Rejects inputs larger than 1MB by default
