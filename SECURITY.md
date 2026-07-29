# Security Policy

TermLens exposes SSH terminal access through a browser. Treat every deployment as a high-risk administrative surface.

## Required Defaults

- Do not expose TermLens without authentication.
- Bind TermLens to `127.0.0.1` and publish it only through an HTTPS reverse proxy.
- Use a dedicated low-privilege service user.
- Require TOTP for every user.
- Use random access links and revoke or rotate them when they are no longer needed.
- Treat generated access URLs as secrets.
- Grant users only the SSH targets they need.
- Do not log terminal output, passwords, private keys, tokens, or SSH commands.
- Do not commit `.env`, databases, access-link output, or bootstrap admin credentials.
- Keep TermLens dependencies, OpenSSH, nginx, and the host OS patched.

## Recommended Hardening

- Restrict access by IP range or VPN when possible.
- Use strong random Basic Auth credentials and rotate them regularly.
- Prefer SSH keys protected by passphrases or short-lived remote credentials.
- Disable password SSH on sensitive remote hosts when operationally possible.
- Monitor service restarts and reverse-proxy access logs.
- Rate-limit repeated failed authentication attempts at the proxy layer.
- Use remote-host controls for command-level authorization. TermLens can revoke a WebSSH session, but it cannot safely enforce every command after the remote shell starts.
- Replace all example paths, domains, users, and ports with values from your own environment before deployment.

## Reporting

Please report security issues through GitHub Security Advisories for this repository. Do not open a public issue for a suspected vulnerability.
