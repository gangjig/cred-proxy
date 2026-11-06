# Changelog

## 0.1.0 - 2026-11-06

- Initial release.
- Declared-permissions config: credentials resolved from an environment
  variable or a file; routes fix an upstream, a credential, a header, and a
  header template.
- Placeholder swap at egress: agents send `proxy:<credential-name>` and
  never see the real secret.
- Undeclared routes and mismatched placeholders are refused with HTTP 403
  before any upstream call.
- Exact-secret redaction of upstream response bodies and headers.
- Secret-free audit log (in memory, plus optional JSONL file).
- Loopback-only bind by default; non-loopback requires `--allow-remote`.
- CLI: `check`, `serve`, `demo`. Standard library only.
