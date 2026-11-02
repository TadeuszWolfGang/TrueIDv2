# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.8.x   | ✅ Current |
| < 0.8   | ❌         |

## Reporting a Vulnerability

If you discover a security vulnerability in TrueID, **please do not open a public issue.**

Report it privately through [GitHub Security Advisories](https://github.com/TadeuszWolfGang/TrueIDv2/security/advisories).
Click **Report a vulnerability** and submit the report to the repository maintainers.
You must be signed in to GitHub to use this private reporting channel.

### What to include

- Description of the vulnerability and its potential impact
- Steps to reproduce (proof of concept if possible)
- Affected version(s)
- Any suggested fix or mitigation

### Response timeline

- **Acknowledgement**: within 48 hours
- **Initial assessment**: within 5 business days
- **Fix or mitigation**: best effort, typically within 30 days for critical issues

### Disclosure

We follow coordinated disclosure. We will credit reporters in the release notes
unless they prefer to remain anonymous.

## Security Best Practices for Deployment

- Never expose the engine admin API (port `8080`) outside your internal network.
- Set `TRUEID_DEV_MODE=false` in production.
- Use TLS termination (reverse proxy or native certs) for the web dashboard.
- Rotate `JWT_SECRET`, `ENGINE_SERVICE_TOKEN`, and `CONFIG_ENCRYPTION_KEY` periodically.
- Restrict RADIUS shared secrets to known NAS devices.
- Review the [Deployment Guide](docs/DEPLOYMENT.md) for hardening recommendations.
