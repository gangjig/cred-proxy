# cred-proxy

A local egress proxy that swaps real API credentials in at request time, so
an agent never sees the secrets it uses.

## Why

Agents that call APIs need credentials, and the usual options are both bad:

- Put the key in the agent's context (prompt, config file it can read, tool
  arguments): now any prompt injection, careless log line, or echoed error
  can leak it. A secret the model has seen is a secret you have to assume
  will eventually be repeated somewhere you did not intend.
- Keep the key away from the agent entirely: now the agent cannot call the
  API at all.

cred-proxy is the middle path, borrowed from how managed agent platforms
inject credentials at the network layer:

1. You declare, in one config file, which credentials exist (an environment
   variable or a file each) and which upstream each one may be used for.
2. The agent sends its request to the local proxy with a placeholder header
   value, e.g. `Authorization: proxy:openai`. The placeholder is not a
   secret; it is safe to put in prompts, code, and logs.
3. The proxy checks the request against the declarations, swaps the
   placeholder for the real credential (rendered through a per-route
   template such as `Bearer {secret}`), and forwards the request to the
   declared upstream.
4. Anything the upstream sends back is scrubbed: if the real secret appears
   in the response body or headers, it is replaced with `***REDACTED***`
   before the agent sees it.
5. Every request is written to an audit log (route, method, path,
   credential name, status) that never contains secret values.

Prompt injection can trick an agent into doing many things, but it cannot
exfiltrate a credential the agent has never seen.

## Quickstart

```bash
pip install -e .          # or: pip install cred-proxy (once published)

export OPENAI_API_KEY=sk-...        # the real secret lives only here
cred-proxy check --config examples/config.example.json
cred-proxy serve --config examples/config.example.json --port 8765
```

The agent then calls the proxy instead of the API directly:

```bash
curl http://127.0.0.1:8765/openai/v1/models \
  -H "Authorization: proxy:openai"
```

The proxy forwards `GET https://api.openai.com/v1/models` with
`Authorization: Bearer sk-...` filled in. Requests to undeclared routes, or
with a placeholder that does not match the route's declared credential, get
an HTTP 403 and the upstream is never contacted.

## Demo

No config, no real secrets:

```bash
cred-proxy demo
```

This starts a throwaway echo upstream and the proxy, then shows three
things: a placeholder being swapped for the real credential upstream, the
secret being redacted out of the echoed response, and undeclared
routes/credentials being refused.

## Config format

```json
{
  "credentials": {
    "openai": { "env": "OPENAI_API_KEY" },
    "github": { "file": "~/.secrets/github-token" }
  },
  "routes": [
    { "name": "openai", "upstream": "https://api.openai.com",
      "credential": "openai" },
    { "name": "github", "upstream": "https://api.github.com",
      "credential": "github", "template": "token {secret}" }
  ]
}
```

- Each credential sets exactly one of `env` (environment variable name) or
  `file` (path to a file containing the secret).
- Each route fixes its upstream; the agent chooses only the path suffix
  after `/<route-name>`.
- `header` defaults to `Authorization`; `template` defaults to
  `Bearer {secret}` and must contain `{secret}`.
- The placeholder an agent sends is `proxy:<credential-name>`, as the whole
  header value.

## Security model

What this does:

- Keeps secret values out of the agent's context, prompts, tool arguments,
  and the audit log.
- Limits each credential to the upstreams you declared for it. An agent
  (or an injection) cannot ask the proxy to send a credential anywhere
  else: undeclared routes and mismatched placeholders are refused before
  any upstream call.
- Redacts the exact secret string from upstream responses, so an upstream
  that echoes your key cannot hand it to the agent.
- Binds to 127.0.0.1 by default and refuses a non-loopback bind unless you
  pass `--allow-remote`.

What this does not do:

- It does not stop an agent from *using* a credential through the proxy for
  its declared purpose — that is the point. Declare narrowly: one route per
  upstream, one credential per route, and prefer scoped/read-only keys.
- Redaction matches the exact secret string; it is not a general DLP
  filter.
- It is an HTTP proxy for APIs that take header credentials, not a TLS
  MITM and not a sandbox.

## Development

```bash
python -m pytest     # standard library only; no third-party dependencies
```

## Source

Inspired by Philipp Schmid's "7 Things Your AI Coworker Needs", which
builds a financial AI coworker on Gemini Managed Agents and injects real
credentials at the network proxy layer — never inside the agent's context —
plus an approval hook and scheduled triggers:
https://www.youtube.com/watch?v=EtZwTYahfek (surfaced in the author's daily
AI digest, 2026-11-06).

## Build your own

This repository is small enough to regenerate from a prompt. Paste the
following into an LLM and it should produce a closely similar project:

> Write a Python 3.10+ command-line tool called "cred-proxy", standard
> library only, with a src layout, pyproject.toml, MIT license, README, and
> a pytest suite. Purpose: a local HTTP egress proxy that keeps real API
> credentials out of an AI agent's context. Behavior: (1) A JSON config
> declares credentials, each resolved from an environment variable or a
> file, and routes, each fixing an upstream base URL, one credential, an
> auth header name (default "Authorization"), and a header template
> containing "{secret}" (default "Bearer {secret}"); invalid configs
> (duplicate route names, undeclared credentials, templates without
> "{secret}", non-http(s) upstreams, credentials with both or neither of
> env/file) are rejected with clear errors. (2) The agent calls
> http://127.0.0.1:<port>/<route>/<path> with the header value
> "proxy:<credential-name>" as a placeholder; the proxy refuses undeclared
> routes and mismatched placeholders with HTTP 403 without contacting the
> upstream, otherwise swaps in the real credential rendered through the
> template and forwards method, path, query, headers, and body to the
> upstream. (3) The real secret is redacted (replaced with
> "***REDACTED***") from response bodies and headers before returning them.
> (4) An audit log (in memory and optional JSONL file) records time, route,
> method, path, credential name, status, and result — never secret values.
> (5) The server binds 127.0.0.1 by default and refuses non-loopback binds
> unless an explicit allow-remote flag is passed; startup fails fast if a
> declared credential cannot be resolved. CLI subcommands: "check"
> (validate a config, print resolvable credentials masked and the declared
> routes), "serve" (run the proxy), and "demo" (spin up a throwaway echo
> upstream plus the proxy and print a three-step demonstration: swap-in,
> redaction, refusal). Tests must cover config validation, secret
> resolution and redaction, and live proxy behavior (swap, redaction in
> body and headers, refusals without upstream calls, path/query/body
> forwarding, status passthrough, audit log contents).

## License

MIT
