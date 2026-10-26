# Repo Guardian

**A local-first repository readiness and hygiene auditor built with Rust + Axum.**

Repo Guardian helps developers catch common project-publishing problems before a repository goes public, gets handed to a teammate, or enters a deployment pipeline. It combines a small Rust HTTP API with a responsive browser dashboard. Scanning happens on the machine running the service; the application has no telemetry, accounts, or external API calls.

> **Important:** this is a baseline heuristic checker, not a full security audit. Review findings manually and use dedicated secret scanners, dependency auditing, and code analysis for production assurance.

## Why this project?

- **Useful in everyday engineering:** checks repository hygiene and common accidental-secret patterns.
- **Local-first by default:** no source files are uploaded to a third party.
- **Readable findings:** severity, file/line, explanation, and a practical remediation.
- **Small operational footprint:** one Rust binary plus static web assets.
- **GitHub-ready:** CI, tests, issue/PR templates, license, and reproducible build guidance.

## Features

- Detects common missing baseline files: `README.md`, `LICENSE`, `.gitignore`, GitHub Actions workflows.
- Checks for common dependency lockfiles.
- Flags `.env` / `.env.local` files and likely private-key files.
- Heuristically scans small text files for private-key headers, AWS access-key IDs, GitHub token formats, and credential assignments.
- Skips common generated/vendor directories (`target`, `node_modules`, `.git`, etc.) and does not follow symlinks.
- Provides a score, severity filters, and downloadable JSON report.
- Enforces a configurable maximum file count.

## Requirements

- Rust stable (MSRV target: 1.78; CI uses stable)
- Cargo
- A modern browser

## Quick start

```bash
git clone https://github.com/YOUR-USERNAME/repo-guardian.git
cd repo-guardian
cp .env.example .env
cargo run
```

Open [http://127.0.0.1:8787](http://127.0.0.1:8787). Enter the **absolute path** to a repository directory, then choose **Scan repository**.

Windows PowerShell equivalent for environment file:

```powershell
Copy-Item .env.example .env
cargo run
```

The browser cannot browse local folders directly, so you enter the path manually. The Rust server process must have permission to read the selected directory.

## Configuration

Configuration is loaded from environment variables; `.env` is optional and ignored by Git.

| Variable | Default | Description |
|---|---|---|
| `HOST` | `127.0.0.1` | Bind address. Keep loopback for local use. |
| `PORT` | `8787` | HTTP port. |
| `RUST_LOG` | `repo_guardian=info,tower_http=info` | Structured request/application log filter. |
| `MAX_FILES` | `20000` | Maximum files considered in one scan. |

**Security note:** the service accepts a local directory path and reads files accessible to the server process. Keep it bound to loopback. Do not expose it to a LAN or public network without authentication, authorization, and additional hardening. It does not return matched secret contents, but file paths and line numbers are included in the report.

## API

### `GET /api/health`

Returns a small health response:

```json
{ "status": "ok", "service": "repo-guardian" }
```

### `POST /api/scan`

Request:

```json
{ "path": "/absolute/path/to/repository" }
```

Response includes repository name, readiness score, summary counts, findings, file count, and whether the scan hit its file limit. Error responses include `error` and `hint`.

Example:

```bash
curl -s http://127.0.0.1:8787/api/scan \
  -H 'content-type: application/json' \
  -d '{"path":"/absolute/path/to/repository"}'
```

## Development

```bash
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo run
```

CI runs formatting, Clippy, and tests on pushes and pull requests.

## Repository layout

```text
repo-guardian/
├── .github/
│   ├── ISSUE_TEMPLATE/bug_report.md
│   ├── workflows/ci.yml
│   └── pull_request_template.md
├── src/
│   ├── main.rs          # Axum HTTP server and API validation
│   └── scanner.rs       # Filesystem walk, heuristics, findings, tests
├── web/
│   ├── index.html       # Accessible dashboard structure
│   ├── styles.css       # Responsive dark UI
│   └── app.js           # API calls, filters, JSON export
├── .env.example
├── .gitignore
├── Cargo.toml
├── deny.toml
├── LICENSE
├── README.md
└── rustfmt.toml
```

## Known limitations

- Secret detection is heuristic: false positives and false negatives are possible.
- The score is a prioritization aid, not a compliance or security rating.
- Dependency vulnerability checks are not performed automatically. For Rust projects, consider `cargo audit`; for broader repos, use the relevant ecosystem's advisory tools.
- The browser UI accepts a path; it cannot open a native directory picker.
- The scanner skips files larger than 2 MiB and common binary formats.
- Symlinks are not followed; nested repository contents inside ignored directories are not scanned.
- The current scan runs locally but can still consume CPU and disk I/O on large trees. Adjust `MAX_FILES` thoughtfully.

## Security reporting

Please do not publish live credentials in issues. For a suspected security issue, contact the repository maintainer privately and include a minimal reproduction without secrets.

## Suggested roadmap

- Add SARIF export for GitHub Code Scanning.
- Add configurable rules and baseline suppression.
- Add ignore-file support and a scan diff.
- Add platform-native directory picker for a desktop wrapper.
- Add optional `cargo audit` integration with explicit user consent.

## License

MIT. See [LICENSE](LICENSE).
