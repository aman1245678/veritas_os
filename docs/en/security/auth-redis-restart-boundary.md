# Authentication Redis restart boundary

The authentication factory checks Redis connectivity, not retained-state
identity or persistence configuration. A reachable empty Redis store can accept
a previously used nonce. Production fail-closed behavior during an outage does
not by itself prevent replay after a reachable replacement loses its records.

## Bounded process-restart tests

`veritas_os/tests/test_auth_real_redis_processes.py` compares two private,
disposable Redis profiles, both with automatic RDB snapshots disabled:

| Profile | After SIGTERM/restart | After SIGKILL/restart |
| --- | --- | --- |
| `appendonly no` | Expect used nonce/rate state to be lost and the nonce to be accepted again | Same expected limitation |
| `appendonly yes`, `appendfsync always`, `maxmemory-policy noeviction` | Expect used nonce, remaining TTL and rate counter to survive | Same expected bounded retention |

Each restart reopens the exact same fixture directory and settings with a new
Redis PID. Fresh worker connections exercise the actual auth-store wrappers;
a fresh nonce must still be accepted, preventing an unavailable backend from
masquerading as a successful replay refusal. The nonce TTL must remain positive
and must not be extended by restart. All fixture data is synthetic and removed.

The dedicated `Auth Real Redis Processes` workflow requires all eight cases,
zero skips/errors/failures, and SHA-bound JUnit/identity artifacts. The volatile
profile passing is evidence of a limitation, not successful replay protection.

## Deployment implications and limits

For deployments requiring nonce retention across Redis process restart,
operators must separately review persistent storage, AOF/fsync configuration,
write-error behavior, eviction controls and key retention. The fixture's
`appendfsync always` setting is a tested profile, not automatically enforced by
VERITAS and not a universal deployment recommendation or performance guarantee.

This test does not demonstrate host reboot/power-loss recovery, disk loss,
corrupt/truncated AOF handling, backup rollback, administrator deletion,
replication/failover, network partitions, different Redis versions, HTTP
replay refusal or external-effect idempotency. Stable state identity and
independent rollback detection remain separate requirements. Redis restart
must not be reported as safe solely because the service becomes reachable.
