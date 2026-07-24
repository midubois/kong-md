# Security Review — Kong Gateway (Production-Deployment Assessment)

**Scope:** Full repository (`kong-md`), audited as if deployed to production.
**Method:** Manual SAST-style pattern hunting (dangerous sinks, TLS-verify bypasses, insecure defaults, hardcoded secrets, dynamic code execution) with manual data-flow tracing.
**Result:** Two high-confidence findings. Both are longstanding design defects (not introduced by a pending diff) that matter specifically for a production deployment.

---

## Vuln 1: TLS certificate verification disabled — AWS Lambda plugin

- **File:** `kong/plugins/aws-lambda/handler.lua:158` (also `:116`, `:131`)
- **Severity:** Medium (High impact, requires on-path / active-MITM position)
- **Category:** `certificate_validation_bypass` / CWE-295
- **Confidence:** 8/10

### Description
The plugin creates its AWS Lambda, STS AssumeRole, and web-identity STS service clients with `ssl_verify = false` hardcoded. The value is unconditional — there is no schema field to turn verification on — and the code comment (`-- TODO: set this default to true in the next major version`) acknowledges it. All three calls also honor `http_proxy` / `https_proxy` from `conf.proxy_url`, so the connection frequently traverses a configured egress proxy.

### Exploit Scenario
An attacker positioned to actively intercept the Kong→AWS connection — a compromised or malicious egress proxy (`proxy_url`), DNS spoofing, or a compromised network segment — presents a self-signed certificate. Because `ssl_verify = false`, Kong accepts it and completes the TLS handshake with the attacker. The attacker can then:

- Read the full Lambda invocation payload, which is the serialized proxied HTTP request (headers, body, client credentials such as `Authorization` / API keys).
- Read the STS `AssumeRole` response (line 131), which returns **temporary AWS credentials** (AccessKeyId, SecretAccessKey, SessionToken) — direct credential theft granting the assumed role's privileges.
- Tamper with the Lambda response returned to the client.

### Recommendation
Default `ssl_verify = true` for the Lambda, STS, and web-identity clients, and expose a schema field (e.g. `aws_ssl_verify`) so operators can opt out only for testing. Ensure `lua_ssl_trusted_certificate` covers the Amazon CA bundle.

---

## Vuln 2: TLS certificate verification disabled — HTTP Log plugin

- **File:** `kong/plugins/http-log/handler.lua:132`
- **Severity:** Medium (requires active MITM on the log-shipping path)
- **Category:** `certificate_validation_bypass` / CWE-295
- **Confidence:** 8/10

### Description
The plugin ships log payloads to the operator-configured HTTPS endpoint via `httpc:request_uri(log_server_url, { ... ssl_verify = false })`. The flag is hardcoded and unconditional, so even an `https://` log target is delivered over an unauthenticated TLS channel. The log payload is the serialized request/response record, and `conf.headers` may carry an `Authorization` header to the log server.

### Exploit Scenario
An attacker who can actively intercept the Kong→log-server connection (malicious network hop, spoofed DNS for the log host, or a rogue host at the configured address) presents any certificate; Kong accepts it and streams the logs. Depending on the log serializer configuration, these records can include client request headers (API keys, bearer tokens, cookies), request bodies, and PII — all disclosed to the attacker, plus any bearer token configured in `conf.headers` for the log endpoint.

### Recommendation
Verify certificates by default when the target scheme is `https`. Add an `ssl_verify` schema field (defaulting to `true`) rather than hardcoding `false`, mirroring how upstream/Redis TLS options are exposed elsewhere in the codebase (`tools/redis/schema.lua`).

---

## Reviewed and Considered Safe (context, not findings)

- **`kong/db/strategies/postgres/init.lua` `load()` / `compile()`** — compiles query-builder functions from **schema metadata** (entity/field names), with runtime values passed as `$N` bind parameters. No user-controlled data reaches the compiled string; not an injection sink.
- **pre-function / post-function plugins (`loadstring`)** — gated by `untrusted_lua = sandbox` (the default in `templates/kong_defaults.lua:207`), so admin-supplied Lua runs sandboxed rather than as unrestricted RCE.
- **Default listeners** — `admin_listen` and `status_listen` bind to `127.0.0.1` by default; the Admin API is not exposed to the network out of the box. (Operators must still avoid rebinding it to `0.0.0.0` without auth.)
- **`cmd/hybrid.lua:51` `os.execute("chmod … " .. cert_file)`** — `cert_file` is a local CLI argument to `kong hybrid gen_cert`; trusted-input per CLI precedent, not a remote attack surface.
- **No hardcoded secrets** were found in non-test Lua source.

**Bottom line:** No exploitable injection, auth-bypass, or RCE was found in Kong core via this review. The actionable production risks are the two hardcoded `ssl_verify = false` TLS bypasses above — both permit credential/PII disclosure to an active on-path attacker and both should be made verifiable-by-default with an explicit opt-out.
