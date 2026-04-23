# AI Contributor Guide For Diode Client

This file is for coding agents and AI-assisted contributors working in this repository.

The job is not just to make code compile. The job is to make changes that look native to this codebase, stay inside the right package boundary, and do not introduce avoidable behavior drift.

## What This Repo Is

`diode_client` is a Go CLI and networking client. Most work falls into a few clear areas:

- CLI entrypoints and subcommands
- shared config and process behavior
- relay/network transport and concurrency
- focused helpers for file transfer, parsing, and protocol/domain logic

When making a change, understand which of those areas owns the behavior before editing anything.

## How To Start

Before changing code:

- Identify the owning package instead of adding logic wherever you first found a call site.
- Read the nearest command, helper, and test files in that package.
- Prefer extending an existing pattern already used nearby over introducing a new local style.
- Check whether the surrounding code is older legacy code or newer cleaned-up code; if both exist, follow the newer tested style unless local consistency forces otherwise.

## Folder Structure

Place code according to ownership:

- `cmd/diode/`: main `diode` CLI entrypoint, subcommands, command-specific parsing, and command orchestration
- `command/`: shared command framework used by `cmd/diode`
- `config/`: global configuration, flag types, logging, and process-wide runtime behavior
- `rpc/`: relay transport, connection lifecycle, actor-style concurrency, SOCKS/proxy behavior, and networking internals
- `blockquick/`: implementation of the Blockquick light-client validation protocol
- `filetransfer/`: file listener behavior, path handling, URL building, and shared file transfer helpers
- `contract/`: contract-facing logic
- `edge/`: protocol and network object/data structures
- `db/`: local persistence helpers
- `util/`: low-level helpers that are genuinely generic across the repo
- `cmd/diode/internal/mcptools/`: MCP tool implementations private to the `diode` command tree
- `pkg/gauge/` and `cmd/gauge/`: the separate gauge CLI and its package-specific code
- `resources/`: embedded assets
- `docs/`: documentation and behavior/spec references
- `examples/`: example programs
- `third_party/`: vendored or forked external code

Placement rules:

- Prefer extending the owning package over creating a new top-level package.
- Do not put new helpers in `util/` unless they are broadly reusable outside one subsystem.
- Keep command-only parsing and validation helpers close to the command.
- Touch `third_party/` only when the task is explicitly about the vendored dependency.

## Contributor Rules

### Keep Changes Native

- Follow `gofmt` output and normal Go layout.
- Keep the change footprint as small as possible while still solving the task. Prefer narrow diffs over broad cleanup so review stays easy.
- Keep functions focused. Validate early, return early, and avoid unnecessary nesting.
- Prefer small helpers over large mixed-purpose handlers.
- Avoid one-line wrapper functions unless they create a real boundary or simplify repeated call sites.
- Reuse existing helpers and package patterns before inventing new abstractions.

### Errors

- Prefer returning errors instead of panicking.
- Use concise `fmt.Errorf(...)` messages with local context.
- Validate input before expensive network, RPC, contract, or file operations.
- If a parser or validator has edge cases, move it into a testable helper.

### Logging And CLI Output

- User-facing CLI output should normally go through `config.AppConfig`, `cfg.PrintInfo(...)`, or `cfg.PrintError(...)`.
- Prefer the repo logger for operational logging.
- Reserve direct `fmt.Printf` and `log.Printf` for command help, intentional progress output, examples, tests, or isolated debug tooling.
- Do not add noisy logs in hot paths, retries, or tight loops unless the operator value is clear.

### Comments And Naming

- Add doc comments for exported types and functions.
- Add short rationale comments when concurrency, protocol behavior, or shutdown semantics are easy to misuse.
- Do not add comments that only restate the next line.
- Match local naming: direct names, minimal stutter, descriptive parse/normalize/validate helper names.

## Package-Specific Guidance

### `cmd/diode` and `command`

- New CLI commands should follow the existing command pattern:
  `var <name>Cmd = &command.Command{...}` at package scope, with flag registration in `init()`.
- Keep handlers thin: parse flags, validate arguments, then delegate.
- Match existing CLI wording and behavior instead of introducing a different command UX.
- Shared parsing logic belongs in helpers with unit tests, not embedded inside long handlers.

### `config`

- Treat config, flag behavior, and user-facing printing as centralized concerns.
- Extend existing config structures and helper methods before adding parallel config plumbing elsewhere.
- Put shared runtime behavior here when it affects multiple commands or subsystems.

### `rpc`

- Respect actor ownership. If a type is guarded by `genserver`, do not access or mutate its state ad hoc from other goroutines.
- When changing actor-backed code, make ownership and shutdown behavior obvious in the code.
- Use `sync.Mutex`, `sync.RWMutex`, and `atomic` only when actor ownership is not sufficient.
- Keep concurrency changes narrow and explicit about close order, draining, callback order, and cleanup behavior.
- Keep test hooks obvious and reset them after tests.

### Focused helper packages

- Packages like `filetransfer` should stay small, deterministic, and easy to unit test.
- Path, URL, spec, and normalization helpers should be pure when possible.
- If a helper only serves one subsystem, keep it in that subsystem instead of promoting it too early.

## Tests And Verification

Use the real repo workflows:

- `go test ./...`
- `make format`
- `make lint`
- `go vet ./...`
- `staticcheck -go 1.25 ./...`

Testing expectations:

- Prefer table-driven tests for parsers, validators, and command argument handling.
- Use `t.Parallel()` only when the test is truly safe to run in parallel.
- Use `t.Cleanup(...)` or deferred restores when overriding globals, hooks, or shared package state.
- Add a focused regression test when fixing parsing, framing, shutdown, or concurrency bugs.
- If the change is local, run the narrow package tests first, then `go test ./...`.
- When a task affects real CLI or network behavior, do not stop at unit tests. Spin up isolated `diode` clients with `-dbpath` pointing at temporary database files and manually exercise the changed behavior end to end.
- Use separate `-dbpath` values per client so manual verification does not reuse or corrupt your normal local state.

## Preferred Current Standard

When older and newer code differ, bias toward the newer cleaned-up style already visible in recent `cmd/diode`, `filetransfer`, `config`, and better-tested `rpc` changes:

- early validation
- explicit error returns
- package-local helpers
- thin command handlers
- documented concurrency ownership
- focused regression tests

Do not cargo-cult older patterns just because they exist.

## Legacy Notes

Some older code still contains:

- broader files with mixed responsibilities
- heavier reliance on globals
- direct `fmt.Printf` leftovers
- less explicit concurrency ownership comments

When editing legacy code:

- preserve behavior first
- improve structure only when it is directly relevant to the task
- avoid spreading the legacy pattern into new files

## Done Checklist For AI Contributors

Before handing back a change, verify:

- the diff is as small as practical for the task and does not include unrelated cleanup
- the code lives in the right package
- the change follows the local pattern instead of introducing a new one
- parsing/validation logic is testable and tested when needed
- CLI output and logging use the expected repo pathways
- concurrency edits preserve ownership and shutdown semantics
- if behavior changed at the CLI or network level, isolated clients were started with `-dbpath` and the flow was manually tested
- verification was run, or you clearly state what was not run
