# Poll routing correction (wrong-cluster-v1)

This optional protocol lets a service correct a client's polling placement while
keeping the configured endpoint and residency fixed. Routing tokens are opaque;
clients never decode a cluster or construct an endpoint from them. Ordinary edge
routing and services that do not implement corrections keep working unchanged.

## Wire exchange

Every supporting client advertises `wrong-cluster-v1` in the common
[`X-Tunnel-Client-Capabilities` header](protocol.md#tunnel-client-capabilities)
on all control-plane requests. A poll includes:

```http
GET /v1/tunnels/<tunnel_id>/poll?limit=25&timeout_ms=30000
X-Tunnel-Client-Capabilities: wrong-cluster-v1
```

The first poll is tokenless. A service may return the following **only** when it
has independently enabled corrections and the current request's parsed
capability set contains `wrong-cluster-v1`. Comma-separated values and repeated
field lines combine into a set; duplicate names and other valid unknown names
are allowed. Missing, malformed, over-limit, or unsupported declarations do not
authorize corrections. Check each poll independently, including when different
client versions share a tunnel. This capability's behavior is specific to
polling; it grants no retry permission for other operations.

```http
HTTP/1.1 409 Conflict
Content-Type: application/json
X-Tunnel-Shard-Token: opaque-placement-token
Retry-After: 1

{"error":{"code":"wrong_cluster","policy_revision":42}}
```

The next poll uses the exact same configured endpoint, tunnel and credentials,
with `X-Tunnel-Shard-Token: opaque-placement-token`. A `200` response (including
`{"commands":[]}`) or `204` retains this token. A successful response never learns
a polling token from response headers or command payloads.

Validation rules:

- Only HTTP `409` with the exact JSON `error.code` string `wrong_cluster` is a
  correction. Ordinary `409` errors retain ordinary error behavior.
- The replacement header is required exactly once. Its value is 1–4096 bytes of
  visible ASCII (`0x21`–`0x7e`) excluding comma. Whitespace, control characters,
  non-ASCII, comma-coalesced headers and empty/oversized tokens are rejected.
  These rules apply only to replacement polling tokens, not legacy command
  tokens.
- `error.policy_revision` is required: a JSON integer from 0 through
  9007199254740991 inclusive. Strings, null, negatives, fractional or exponent
  notation, and overflow are invalid. Revisions form a monotonically increasing
  total order within the tunnel's configured endpoint/environment/residency.
  The service must never recycle a revision for different placement.
- The response header is the canonical token location; the declared JSON body
  contains only `code` and `policy_revision`. As a defensive compatibility rule,
  if a sender additionally supplies `error.shard_token`, the client requires a
  non-null string exactly equal to the header. There is no `routing_shard_token`,
  destination URL or client-visible cluster field. Protocol JSON keys are
  case-sensitive; duplicate
  `error`, `code`, `policy_revision` or `shard_token` fields are rejected rather
  than merged or resolved by taking the last value. Unknown metadata is ignored.
- Correction error bodies are limited to 64 KiB. Missing/malformed fields or
  conflicting copies cannot change cached state. Diagnostics do not echo the
  body, token or server-supplied message of a correction.

Polling exchanges are excluded from raw HTTP dumps, including when unsafe raw
logging is enabled, because both requests and responses can carry routing tokens.

## Polling state and recovery

State belongs to one client instance, whose tunnel ID and endpoint are immutable.
It is never global, persisted, or shared between instances. A restarted client or
new tunnel starts tokenless. The revision watermark and its accepted token stay
in memory even when recovery temporarily clears the outbound token.

Each poll makes **one** HTTP attempt under the existing poll deadline. Corrections
return through the ordinary poller's failure path, so every retry waits using
its existing exponential backoff with jitter (defaults 200 ms to 10 seconds).
Valid `Retry-After` delta-seconds or HTTP dates supply a minimum delay, capped at
60 seconds; malformed/expired values use backoff. Cancellation interrupts both
requests and sleeps. Only a successful poll resets backoff/readiness; accepting
a correction is not a successful poll.

A valid newer revision replaces the token. Older revisions do not change the
placement. An equal revision can restore the same accepted token after bootstrap
but cannot install a different token: conflicts clear the active token and cause
same-endpoint bootstrap. Repeated identical corrections also remain errors and
never bypass backoff.

After three valid correction responses without a successful poll, clear the
active token and reset the correction counter; the next attempt is tokenless.
This bounds each correction round and permits recovery if bootstrap subsequently
returns a usable correction. Continued rejection remains unavailable with
increasing/capped backoff, rather than restarting an immediate correction loop.

After three cached-destination failures without a successful poll or correction
(transport errors, including interrupted body reads, other than caller
cancellation; HTTP 408; or HTTP 5xx), clear that attempt's active token and
make the next attempt tokenless. A valid correction or success resets this
failure counter. Authentication, rate-limit, malformed-correction and ordinary
client errors do not cause token eviction. Tokenless failures remain unavailable
under ordinary backoff. Recovery never recreates the tunnel.

Every request snapshots a generation. State-bearing results commit only if that
generation is still current, and advance it atomically. Late corrections,
successes and failures cannot overwrite or clear state already changed by a
newer completed request. No transport lock is held across network I/O.

Poll redirects are rejected before another request is sent, including redirects
to the same origin. No server-supplied URL is followed. EU bootstrap must be
reachable through the configured EU endpoint; unavailable EU infrastructure is
unavailability, never permission to fall back to global infrastructure.

## Command tokens and operation execution

Every response **and notification** echoes its command's original `shard_token`
in `X-Tunnel-Shard-Token`, even after polling moves or clears its token. Command
tokens retain their existing opaque semantics and are never validated as new
placement tokens. The polling cache is not consulted by response delivery.
Existing response delivery retry rules remain unchanged; `wrong_cluster` adds
no retry, queue migration, draining, replay of tool execution, or tunnel creation.

The [complete request/response sequence fixtures](../pkg/controlplane/internal/testdata/routing_sequences.json)
provide executable examples of bootstrap, successful empty polls, revision
conflicts, malformed rejections and unavailable-destination recovery. Real-client
tests additionally exercise fake-service capability gating and responses plus
notifications from an older command completing after reassignment.

## Release and activation order

Release supporting clients first. They advertise support but require no new
server behavior; older services ignore the new headers. Upgrade/restart begins
with a tokenless poll, with no saved routing state to migrate.

The client capability header is shared by optional client features. This release
adds `wrong-cluster-v1` as its first capability; it does not alter
`X-Tunnel-MCP-Server-Info` or existing command/response JSON payloads.

Enable corrections separately, only for capable clients, after the service and
edge have compatible placement policy, token validation/routing, original-command
routing, and independently available bootstrap within each residency. Clients
must be released before that activation. Edge routing remains the preferred path.
This change contains protocol declarations and client compatibility only;
production rejection emission and routing activation remain disabled.

Reassignment can interrupt availability for a few minutes. It does not migrate
queued work or replay uncertain operations. Clients that have not upgraded must
continue to receive the existing service behavior.
