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

The overlapping control path for CLI flags, CLI config changes, the config API, and `join` is centralized in the descriptor registry in [cmd/diode/control_shared.go](cmd/diode/control_shared.go).

When adding a new shared control:

1. Add one `ControlSpec` with the canonical key, aliases, value kind, apply/reset behavior, persistence serializer, effects, HTTP exposure, and any shared CLI flag definitions.
2. If it should survive YAML config files, reuse an existing `config.Config` field when possible and ensure it has the correct YAML tag in [config/flag.go](config/flag.go).
3. If the setting changes live runtime behavior beyond existing service or published-port effects, extend `ReconcileControlServices()` or `ReconcilePublishedPorts()`.
4. Keep adapters thin: use `ControlPatch`/`ApplyControlPatch` from CLI config mutations, config API request fields, and contract properties instead of reimplementing behavior in each file.
5. Add focused regression coverage in [cmd/diode/control_shared_test.go](cmd/diode/control_shared_test.go).

The expected outcome is that a new shared control usually needs one descriptor plus focused tests. Persistence keys, aliases, HTTP controls, and shared CLI flags should come from that descriptor.

## Compatibility Rules

- Do not duplicate shared-control behavior separately in `config.go`, `config_server.go`, and `join.go`.
- Keep long-standing DB meanings stable. For example, `private` already means the client private key in the local store.
- If a new shared control would collide with an existing DB key, keep the canonical runtime key and set the descriptor `StorageKey` to the compatible persisted name.
- Reuse existing helpers such as bind parsing, published-port parsing, logger reload, and log-stats restart.

## Style Expectations

- Follow `gofmt`.
- Prefer early validation and explicit error returns.
- Use the existing config/logger pathways for user-facing output.
- Add tests for parsing, persistence, reconciliation, or shutdown edge cases when behavior changes.

## Pull Requests

A good PR for this repo is small, package-local, and explicit about behavior changes. If you changed CLI or daemon behavior, include the commands or tests you ran to verify it.
