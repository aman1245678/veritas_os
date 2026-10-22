# Authentication Redis restart boundary

In production/strict profiles, the authentication factory and API startup check
read back Redis retention configuration and current AOF write health. They
require `appendonly=yes`, `appendfsync=always`,
`no-appendfsync-on-rewrite=no`, `maxmemory-policy=noeviction`,
`aof_enabled=1` and `aof_last_write_status=ok`. Missing/unsupported settings,
unhealthy writes and inspection errors refuse startup, including on one worker.
These checks use only `CONFIG GET` for those four names and `INFO persistence`;
they never change Redis configuration. The Redis ACL must permit those reads.

Retained-state identity is not checked. A reachable empty Redis store with the
accepted settings can still accept a previously used nonce. Startup refusal of
volatile settings is not proof against replacement, deletion or backup rollback.

## Bounded process-restart tests

`veritas_os/tests/test_auth_real_redis_processes.py` compares two private,
disposable Redis profiles, both with automatic RDB snapshots disabled:

| Profile | After SIGTERM/restart | After SIGKILL/restart |
| --- | --- | --- |
| `appendonly no` (explicit local diagnostic profile) | Expect used nonce/rate state to be lost and the nonce to be accepted again | Same expected limitation |
| `appendonly yes`, `appendfsync always`, `maxmemory-policy noeviction` | Expect used nonce, remaining TTL and rate counter to survive | Same expected bounded retention |

Each restart reopens the exact same fixture directory and settings with a new
Redis PID. Fresh worker connections exercise the actual auth-store wrappers;
a fresh nonce must still be accepted, preventing an unavailable backend from
masquerading as a successful replay refusal. The nonce TTL must remain positive
and must not be extended by restart. All fixture data is synthetic and removed.

The dedicated `Auth Real Redis Processes` workflow requires all twelve cases,
zero skips/errors/failures, and SHA-bound JUnit/identity artifacts. The volatile
profile passing is evidence of a limitation, not successful replay protection.
Four additional cases require the actual strict factory and startup guard to
refuse volatile, delayed-fsync, eviction and rewrite-skips-fsync configurations.
Normal protected tests use AOF; volatile diagnostics explicitly use local mode.

## Deployment implications and limits

For deployments requiring nonce retention across Redis process restart,
operators must separately review persistent storage, AOF/fsync configuration,
write-error behavior, eviction controls and key retention. The fixture's
`appendfsync always` setting is now required by strict Redis startup, not set by
VERITAS. This stricter startup requirement may reject an existing deployment
until its owner separately provisions compatible storage/configuration and ACLs.
It is not a performance guarantee. The check is a startup/factory snapshot and
does not monitor later configuration changes or disk failures.

This test does not demonstrate host reboot/power-loss recovery, disk loss,
corrupt/truncated AOF handling, backup rollback, administrator deletion,
replication/failover, network partitions, different Redis versions, HTTP
replay refusal or external-effect idempotency. Stable state identity and
independent rollback detection remain separate requirements. Redis restart
must not be reported as safe solely because the service becomes reachable.
