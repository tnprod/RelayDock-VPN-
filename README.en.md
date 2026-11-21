# RelayDock

**Replace your exit server without replacing everyone's connection links.**

[Windows download](https://github.com/tnprod/RelayDock-VPN-/releases) · [Русский README](README.md) · [Issues](https://github.com/tnprod/RelayDock-VPN-/issues)

A personal VPN often starts with one VPS and one link. Moving to another provider means moving the configuration and asking everyone to update their apps. RelayDock separates the stable entry server from the replaceable exit server, so existing links can keep working when you switch exits.

It runs on your computer and opens a local browser interface. Once configured, the VPS services keep running even when RelayDock is closed.

```text
Client → stable entry VPS → replaceable exit VPS → internet
```

## Available in 2.0 beta 1

- SSH access using a password, private key, or agent.
- VLESS + REALITY through Xray and optional Telegram MTProxy.
- Direct connections or separate entry/exit servers.
- Saved profiles, connection links, and locally generated QR codes.
- Exit replacement with real HTTPS and Telegram protocol checks. An unconfirmed entry switch rolls back after 120 seconds.
- Configurable ports and advanced connection options.

The old exit is not deleted. RelayDock creates separate systemd services and refuses to take over a port occupied by another service. With active UFW, it adds rules for the selected TCP ports. Provider firewalls remain your responsibility.

## Try it

The desktop build supports Windows x64. Managed servers currently require **Ubuntu 24.04 x86_64**, Python 3, systemd, and root or passwordless sudo. Use one VPS for direct mode or two for a separate entry and exit.

Download and fully extract the archive from [Releases](https://github.com/tnprod/RelayDock-VPN-/releases), then run `RelayDock.exe`. Add your servers, verify their SSH host fingerprints against a trusted source, and choose «Настроить VPN» in «Подключения». Review the installation plan, configure the connection, and open «Ссылки и QR». Use «Заменить выход» to switch exits. The interface currently uses Russian.

Start with test servers. The application installs services and changes network settings. Keep access to your provider's server console, and run only one RelayDock instance against the same setup.

In direct mode, preserving the address across IP changes requires your own domain and a DNS update. A stable link cannot prevent the entry address itself from being blocked.

## Beta limits

Installation and real HTTPS/Telegram traffic were checked on three VPS instances. Exit switching and switching back preserved the connection links exactly. There are 28 passing automated tests and additional checks of the Windows executable. See [verification details](docs/verification.md).

Arbitrary 3x-ui management, full panel migration, SSH hardening, encrypted cross-computer export, and packaged macOS/Linux builds are not implemented. New connections use a separate Xray service. Legacy import only supports the specific `codex-forward-*` and `codex-exit-*` service layout handled by the importer.

The Windows build has not been tested on a separate clean machine. Power loss and all network failure scenarios have not been simulated. There has been no independent security audit. Rollback is useful protection, but it does not replace backups or console access.

## Data and privacy

No RelayDock cloud account or telemetry. The interface listens on loopback only. The application contacts your servers, official component releases, and external connectivity test endpoints.

Windows data lives in `%LOCALAPPDATA%\RelayDock`. Profile secrets and uploaded SSH keys are encrypted; the master key is protected by Windows DPAPI for the current user. SSH passwords are not saved. On the source Linux version, the master key relies on file permissions.

Profile snapshots share the same local database. They are not independent disaster-recovery backups. A database without its vault key cannot restore secrets, and copying the files to another computer is not a supported migration method.

Never post private keys, passwords, your data directory, full connection links, or QR codes in public issues.

## Help shape the project

We need first-hand reports: does it work on your clean Windows installation, where did the instructions become confusing, and what happened when setup failed? Open an [issue](https://github.com/tnprod/RelayDock-VPN-/issues) with redacted details. For code contributions, see [CONTRIBUTING.md](CONTRIBUTING.md).

## Development

Python 3.11+:

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
.\.venv\Scripts\python launch.py
```

The built frontend is included. To rebuild it, run `pnpm install --frozen-lockfile` and `pnpm run build` in `frontend/`. Install `requirements-dev.txt` and run `python -m pytest tests -q` for tests. `build_windows.ps1` creates a Windows build. Source runs and self-built packages download pinned, SHA-256-verified Xray/mtg components when needed; the published Windows package includes them.

Stack: Python, FastAPI, AsyncSSH, SQLite, React, TypeScript. [Architecture](docs/architecture.md).

RelayDock source is [MIT licensed](LICENSE). Bundled components retain their own licenses: [THIRD_PARTY.md](THIRD_PARTY.md).
