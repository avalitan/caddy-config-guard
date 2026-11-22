# Caddy Config Guard (experimental)

Caddy HTTP middleware for validating **untrusted Caddy JSON route fragments**
submitted through a separately authenticated/authorized Admin API gateway.

**Status: experimental prototype, not yet security-audited or safe to deploy as
the sole security boundary.** This project intentionally fails closed for
unrecognized modules, fields and configuration shapes.

## Design

- Uses a **verified mTLS client certificate** (not a user-supplied header);
  the certificate's URI SANs provide optional permission profiles.
- Grants from multiple matching URI SANs are additive. Unknown grants do
  nothing. Default permissions are configured in Caddy.
- Inspects the request JSON without provisioning arbitrary submitted modules.
- Permits only explicitly implemented, schema-checked JSON shapes.
- Validates static upstream IP addresses against allowed CIDRs; no unix
  sockets, hostnames, dynamic upstreams, placeholders or DNS lookups.
- Optional namespace enforcement for `@id` fields, using `~` separator.
- Hard request body limit, clear JSON denials, audit-only mode.
- Preserves and restores the original request body for the next handler.

**Security boundary**: The *existing Admin Gate* must still restrict methods,
paths and the outer site's host matcher. This module does **not** implement
Admin API endpoint authorization. Do **not** put this middleware in front of
`/init` or `/init4`: those requests create trusted outer routes and use a
different JSON shape.

In particular, Caddy's Admin API accepts replacement bodies that aren't
necessarily full route objects. This first version rejects those requests,
rather than trying to validate arbitrary Config API paths.

## Configuration

Example for the existing `gate_self_management` handler (immediately before
the Unix-socket `reverse_proxy`, with mTLS enabled on `admin_gate`):

```json
{
  "handler": "config_guard",
  "policy_uri_prefix": "urn:avalitan:caddy:guard:",
  "validate_ids": true,
  "identity_prefix": "site_rules_",
  "separator": "~",
  "max_body_bytes": 1048576,
  "default_policy": {
    "allow_handlers": [
      "reverse_proxy", "static_response", "subroute"
    ],
    "allow_matchers": ["host", "path", "method"],
    "allow_cidrs": ["192.168.2.0/24"]
  },
  "profiles": {
    "advanced": {
      "allow_handlers": ["headers", "rewrite"],
      "allow_matchers": ["header"]
    },
    "management_network": {
      "allow_cidrs": ["10.20.0.0/16"]
    }
  }
}
```

A certificate URI SAN `urn:avalitan:caddy:guard:advanced` enables the
additional `headers`, `rewrite` and `header` matcher permissions;
`urn:avalitan:caddy:guard:management_network` adds a CIDR grant.
Certificates without guard URI SANs receive only `default_policy`.

Set `identity_prefix` to `l4_rules_` for an L4 *ID namespace*, but note
that L4 configuration **is not supported by this HTTP-only validator yet**.
Do not use the same policy to authorize L4 route modifications.

When optional `validate_ids` is true, any submitted `@id` must begin with
`site_rules_<certificate CN>~`. This is a convenience restriction; relying on
certificate CNs requires your CA to issue controlled, validated CN values.

## Supported configuration

- Top-level **HTTP route object** or array of HTTP routes:
  `@id`, `match`, `handle`, `terminal`
- Handlers (only when allowed): `reverse_proxy` with **static literal-IP
  upstreams**, `static_response`, `headers`, `rewrite`, `subroute`
- Matchers (only when allowed): `host`, `path`, `method`, `header`
- All objects are checked for unknown keys, including nested subroutes.

**Not supported**: layer4 routes, dynamic upstreams, TLS reverse proxy
transports, hostname or unix-socket upstreams, regex/expression matchers,
`handle_response`, named routes, plugins not explicitly understood by this
validator, and arbitrary Admin API partial-object updates.

Allowing a handler's name does *not* enable all that module's options: those
must have independent schema/semantic validation before being supported.

## Integration and limitations

The guard checks the incoming HTTP request before any Caddy Admin API
`reverse_proxy` call. It does not wrap or buffer the proxy response and
should not cause the response interception problem encountered with earlier
lease middleware.

`audit_only: true` logs denials but forwards them; **never** enable audit
mode without other effective policy enforcement.

This prototype does not yet address every possible Caddy Admin API patch
shape, JSON duplicate-key ambiguity, request-target normalization or all
network destination hazards. Do not deploy as a complete isolation boundary
until these have been investigated and tested.

## Build

```sh
xcaddy build --with github.com/avalitan/caddy-config-guard
```

Include your existing modules in the full build. Run `go test ./...`
before building; manually test against a **nonproduction** Caddy instance.
