# `mcpg-plugin-backend-ldap`

LDAP / Active Directory backend binding plugin for mcpg (`kind: ldap`).
Binds a configured service account and runs directory **searches** as MCP
**tools** and **resources** — find people, groups, and org data — with the
filter CEL-templated from the tool arguments and the matched entries
returned as JSON.

Part of the legacy → MCP bridge suite. Pairs
with the planned `ldap` **identity** plugin (bind-as-caller, `memberOf` →
roles).

## How it works

One binding = one directory search = one MCP tool (or resource). Per call:

1. The `filter` is CEL-interpolated from the tool arguments; interpolated
   string values are **RFC 4515 LDAP-escaped** so they can't break out of
   the filter (injection defense), exactly as the SOAP backend XML-escapes
   into its envelope.
2. The plugin connects (LDAP or LDAPS), binds the service account (the
   `bind_password` resolves through the gateway credential cache via
   `cred://`), runs the search under `base_dn`/`scope`, and projects the
   matched entries to JSON.
3. Bind/search rejections and transport failures become a structured
   `downstreamError` (the gateway's `isError` signal); transient connect/
   timeout failures are marked retryable.

## Configuration

| Field | Type | Default | Notes |
|---|---|---|---|
| `url` | string (required) | — | `ldap://host:389` or `ldaps://host:636`. Operator-configured (not caller-templated). |
| `bind_dn` | string (required) | — | Service-account bind DN. |
| `bind_password` | string (required) | — | Literal or a whole `cred://…` URI (resolved per call). |
| `base_dn` | string (required) | — | Search base DN. |
| `scope` | `base`\|`one`\|`subtree` | `subtree` | Search scope. |
| `filter` | string (required) | — | LDAP filter, CEL `${arguments.*}`, values LDAP-escaped. |
| `attributes` | `[string]` | `[]` (= all) | Attributes to return. |
| `size_limit` | int | `100` | Client-side cap on returned entries. |
| `timeout_ms` | int | `10000` | connect + bind + search timeout. |

### As a tool

```yaml
plugins:
  - id: dev.mcpg.backend.ldap
    class: backend
    source: { oci: "{{OCI_BASE}}/backend-ldap:<ver>" }
mcp:
  capabilities:
    tools:
      - name: directory.search_people
        description: Find people in the corporate directory.
        input_schema:
          type: object
          properties: { q: { type: string } }
          required: [q]
        backend:
          kind: ldap
          url: "ldaps://dc1.corp.example.com:636"
          bind_dn: "cn=svc-mcpg,ou=svc,dc=corp,dc=example,dc=com"
          bind_password: "cred://vault-ad/svc-mcpg"
          base_dn: "ou=people,dc=corp,dc=example,dc=com"
          scope: subtree
          filter: "(&(objectClass=person)(|(cn=*${arguments.q}*)(mail=*${arguments.q}*)))"
          attributes: [cn, mail, department, manager, memberOf]
```

### As a resource

```yaml
mcp:
  capabilities:
    resources:
      - uri: "ldap://people/{employeeId}"          # resources/read → one entry
        mime_type: application/json
        backend:
          kind: ldap
          url: "ldaps://dc1.corp.example.com:636"
          bind_dn: "cn=svc-mcpg,ou=svc,dc=corp,dc=example,dc=com"
          bind_password: "cred://vault-ad/svc-mcpg"
          base_dn: "ou=people,dc=corp,dc=example,dc=com"
          filter: "(employeeID=${employeeId})"
```

## Response envelope

```jsonc
{
  "toolName": "directory.search_people",
  "profile": "directory.search_people",
  "request":  { "url": "ldaps://…", "baseDn": "ou=people,…", "scope": "subtree",
                "filter": "(&(objectClass=person)(cn=*alice*))", "attributes": ["cn","mail"] },
  "response": { "entries": [ { "dn": "cn=Alice,…", "attributes": { "cn": ["Alice"], "mail": ["a@x"] } } ],
                "count": 1, "durationMs": 12 },
  "downstreamError": null,        // non-null ⇒ isError:true (ldap_error / transport_error)
  "downstreamErrors": [],
  "error": null
}
```

## Security

- **`cred://` boundary.** `cred://` resolves only in `bind_password` (a
  whole-URI service-account secret). It is **rejected** in `filter` (which
  is CEL-templated from caller arguments).
- **Filter injection.** Argument string values are RFC 4515 LDAP-escaped
  before interpolation into the filter.
- **TLS.** LDAPS over rustls. Note: `ldap3` 0.11's only rustls path is the
  legacy `rustls 0.21` / `rustls-webpki 0.101` stack (no modern-rustls
  option; native-tls is banned), so LDAPS reintroduces that transitive
  stack — covered by scoped `deny.toml` ignores (RUSTSEC-2026-0098/-0099/
  -0104). The plugin is an outbound client to an operator-configured
  directory; revisit when ldap3 ships on rustls 0.23.

## Build / test

```bash
nx build mcpg-plugin-backend-ldap
nx test  mcpg-plugin-backend-ldap                                   # unit tests
cargo test -p mcpg-plugin-backend-ldap --features integration-tests  # OpenLDAP (docker)
nx lint  mcpg-plugin-backend-ldap
```

## Scope / deferred

- **`ldap` identity plugin** (bind-as-caller, `memberOf` → roles) — next.
- Native modern-rustls LDAPS — pending an ldap3 upstream release.
- Per-cred connection pooling — v1 connects + binds per call (LDAP connects
  are cheap); add pooling if a hot path needs it.
- Write operations (add/modify) — v1 is read/search only.
