# Contributing

This repository contains the `diode` CLI, shared config/runtime code, networking internals, and a separate `gauge` CLI. Contributions should preserve package boundaries, existing behavior, and the local coding style instead of introducing parallel mechanisms.

## Development Flow

1. Identify the owning package before editing code.
2. Extend an existing local pattern before introducing a new abstraction.
3. Keep command handlers thin and move reusable parsing or validation into testable helpers.
4. Keep diffs small and avoid unrelated cleanup.

## Package Ownership

- `cmd/diode/`: CLI entrypoints, subcommands, command orchestration, command-local parsing
- `command/`: shared command framework
- `config/`: global configuration, logging, config-file persistence, process-wide runtime behavior
- `rpc/`: relay/network transport, SOCKS/proxy runtime, concurrency-heavy internals
- `filetransfer/`: file serving and transfer helpers
- `contract/`, `edge/`, `db/`, `util/`: focused domain and persistence helpers

Prefer extending the owning package over creating a new top-level package.

## Build And Verification

Common verification commands:

```bash
go test ./...
make format
make lint
go vet ./...
staticcheck -go 1.25 ./...
```

If you change CLI or network behavior, also run isolated manual checks with separate `-dbpath` values so you do not reuse your normal local state.

## Adding A Shared Control

The overlapping control path for CLI config changes, the config API, and `join` is centralized in [cmd/diode/control_shared.go](cmd/diode/control_shared.go).

When adding a new shared control:

1. Add the canonical key to `applySharedControlValue()` and `resetSharedControlValue()`.
2. If the value should persist, add it to `persistedSharedControlKeys` and implement DB serialization in `sharedControlDBValue()`.
3. If it should survive YAML config files, reuse an existing `config.Config` field when possible and ensure it has the correct YAML tag in [config/flag.go](config/flag.go).
4. If the setting changes live runtime behavior, extend `ReconcileControlServices()` or `ReconcilePublishedPorts()`.
5. Adapt each interface into the shared key instead of reimplementing the behavior:
   - CLI config mutations: [cmd/diode/config.go](cmd/diode/config.go)
   - Config API: [cmd/diode/config_server.go](cmd/diode/config_server.go)
   - Contract-driven join path: [cmd/diode/join.go](cmd/diode/join.go)
6. Add focused regression coverage in [cmd/diode/control_shared_test.go](cmd/diode/control_shared_test.go).

The expected outcome is that a new shared control usually needs one canonical implementation, one persistence change if needed, one reconciler change if it affects runtime state, and only thin adapter changes per interface.

## Compatibility Rules

- Do not duplicate shared-control behavior separately in `config.go`, `config_server.go`, and `join.go`.
- Keep long-standing DB meanings stable. For example, `private` already means the client private key in the local store.
- If a new shared control would collide with an existing DB key, keep the canonical runtime key and map persistence separately through `sharedControlStorageKey()`.
- Reuse existing helpers such as bind parsing, published-port parsing, logger reload, and log-stats restart.

## Style Expectations

- Follow `gofmt`.
- Prefer early validation and explicit error returns.
- Use the existing config/logger pathways for user-facing output.
- Add tests for parsing, persistence, reconciliation, or shutdown edge cases when behavior changes.

## Pull Requests

A good PR for this repo is small, package-local, and explicit about behavior changes. If you changed CLI or daemon behavior, include the commands or tests you ran to verify it.
