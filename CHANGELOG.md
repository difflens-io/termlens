# Changelog

[中文更新日志](CHANGELOG.zh-CN.md)

## 0.1.0

Initial public release.

### Added

- Added the initial TermLens WebSSH gateway.
- Added a browser terminal based on xterm.js and a Node.js SSH backend based on `ssh2`.
- Added admin-managed users, roles, SSH targets, and per-target permissions.
- Added random per-user access links.
- Added mandatory password + TOTP login with QR-code enrollment.
- Added short-lived one-time terminal tickets before WebSocket connection.
- Added session, access-link, target-permission, and ticket checks before forwarding terminal input.
- Added collapsible connection panel, resizable terminal layout, and fullscreen terminal mode.
- Added systemd and nginx deployment examples.
- Added English and Chinese documentation.
- Added design philosophy, system architecture diagrams, interaction-flow diagrams, deployment steps, and usage guides to the documentation.
- Added a security policy and production hardening guidance.

### Security

- SSH credentials are used only for the current connection and are not stored.
- Access links, terminal tickets, and session tokens are stored as hashes.
- TOTP secrets are encrypted at rest with `TERMLENS_SECRET_KEY`.
- Terminal output is not persisted by the application.
- SSH connection failures shown to users avoid exposing backend connection details.
