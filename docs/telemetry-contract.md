# Telemetry contract (wire format v1)

Producers emit one JSON object per event: one line in a JSON Lines file, or one log line of
the form `{"agent_monitor_event": {...}}` on stdout for collection from pod logs. Any other
log line is ignored and never stored. The format is compatible with the first Agent Monitor
PoC; `policy_authorized` and `policy_denied` were added.

## Fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `id` | string, 1 to 200 chars | yes | unique across all events; reusing an id for different data is an incident |
| `ts` | number | yes | epoch seconds; more than 5 min in the future or older than the retention window is rejected |
| `agent` | string, 1 to 200 chars | yes | must be an identity the source is bound to |
| `run_id` | string, 1 to 200 chars | yes | groups the events of one agent run |
| `type` | string | yes | one of the types below |
| `tool` | string | for `tool_call`, `policy_authorized`, `policy_denied` | tool name as in the policy |
| `args_hash` | string | recommended for `tool_call` | fingerprint of the arguments, never the arguments; without it, repeated calls of a tool count as identical |
| `tokens` | nonnegative integer | no | provider-reported usage; do not estimate |
| `cost_usd` | nonnegative number | no | |
| `latency_ms` | nonnegative number | no | |
| `status` | string | no | see types |
| `citations` | array of strings | no | for `answer` |
| `retrieved` | array of strings | no | for `answer` |
| `attrs` | object | no | only `claim_id`, `verifier`, `error_type`, `usage_available`, `reason`, `approver` are kept, and only scalar values |

Unknown top-level fields are ignored. Booleans are not accepted where numbers are expected.

## Types

| Type | Meaning | `status` |
|---|---|---|
| `run_started` | a run begins | |
| `tool_call` | the agent invoked `tool` | |
| `llm_call` | a model call; `attrs.usage_available=false` when the provider reported no usage | |
| `escalation` | handed over to a human; `attrs.reason` | |
| `policy_authorized` | an approval gate allowed one call of `tool`; `attrs.approver` | |
| `policy_denied` | an approval gate refused `tool`; revokes earlier grants in the run | |
| `claim` | the agent states an outcome; link verifications with `attrs.claim_id` | `fixed` |
| `verification` | an independent check of a claim; `attrs.claim_id`, `attrs.verifier` | `ok` or `failed` |
| `answer` | a RAG answer | `abstained` for a deliberate non-answer without citations |
| `run_finished` | terminal event; `attrs.error_type` on errors | `success`, `escalated`, `error` |

## Argument fingerprints

`agentmon.hash_args(args, key)` returns a 16-hex HMAC-SHA256 of the canonical JSON of the
arguments. Without a key it is a plain SHA-256 prefix: good enough to detect repetition,
but low-entropy arguments such as pod names can be confirmed by guessing. Use a per-producer
secret key when fingerprints leave the producer's trust boundary.

## Reference emitter

`agentmon.emitter.Telemetry` writes this format with `JsonlSink` (one `O_APPEND` write per
event) or `LogSink` (envelope on stdout). Its `run()` context manager always emits
`run_finished`, with status `error` and the exception class as `error_type` when the block
raises.
