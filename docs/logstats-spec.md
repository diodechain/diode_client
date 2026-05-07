# `-logstats` specification

Normative description of the proposed **`-logstats`** global flag: periodically emit **system and process metrics** through the same logging pipeline as normal application logs (stderr, file, `-logtarget` remote leg, etc.), prefixed with **`[STATS]`** so operators and collectors can filter or parse them.

This document is a **design spec**; behavior matches intent here once implemented.

---

## Summary

| Item | Value |
|------|--------|
| **Flag** | **`-logstats`** enables periodic stats; **`-logstats=<period>`** sets the interval in **seconds**. |
| **Default interval** | **60** seconds when `-logstats` is enabled without a numeric value (see **Flag syntax**). |
| **Minimum interval** | **10** seconds; values below 10 are **clamped** to 10 (or rejected at startup—implementation may choose; **clamp** is recommended). |
| **Log prefix** | Every stats line (or block) **begins with** `[STATS]` before the rest of the message. |
| **Level** | **Info** (or a dedicated key if using structured logs; plain text should still show `[STATS]`). |
| **Pipeline** | Same **`config.Logger`** / zap sinks as the rest of the process—respects `-logfilepath`, `-logtarget`, etc. |

---

## Flag syntax

- **`-logstats`** — Enable stats logging with default interval **60** seconds.
- **`-logstats=<period>`** — Enable with interval **`<period>`** seconds. `<period>` must be a **positive integer**. If `<period>` **< 10**, clamp to **10** (recommended) or fail fast with a clear error.
- **Omitting the flag** — Stats logging **disabled** (default).
- **YAML / config file** — Mirror with a field such as `logstats` (e.g. `true` / `60` / `"60s"`—exact encoding is implementation-defined but must match CLI semantics).

**Help text** must state: interval in **seconds**, minimum **10**, default **60** when the flag is enabled without a value.

---

## When to run

- Start the periodic emitter **after** the process logger is initialized (e.g. after `prepareDiode` / `NewLogger`), and only while the main process is running (daemon, long-running command, or any command where metrics are meaningful).
- **One-off commands** that exit immediately may emit **zero** or **one** sample—implementation-defined; prefer **no** stats for sub-second CLIs to avoid noise.
- **Stop** the ticker on graceful shutdown (`Close` / signal) to avoid goroutine leaks.

---

## What to log (recommended set)

All entries are prefixed with **`[STATS]`**. Prefer **one line per tick** (easy to grep) or a **small fixed set of lines** per tick; avoid unbounded cardinality.

Focusing on **host / OS signals** operators care about (memory pressure, CPU, disk headroom, network activity), not Go runtime internals.

| Metric | Notes |
|--------|--------|
| **Uptime** | Time since **process** start—cheap, no extra deps (`time.Since(start)`). **Always include** in the default `[STATS]` line. |
| **Memory** | **Available** and **total** RAM (OS-level), and/or **used %**—surfaces pressure before OOM. |
| **CPU** | **Percent** over the interval (process and/or system—document which). |
| **Load average** | e.g. **1 / 5 / 15 minute** values where the OS exposes them. |
| **Disk** | **Available** and **total** space on the filesystem for the volume containing **`-dbpath`**. |
| **Network I/O deltas** | **Bytes received** and **bytes sent** during the **last stats interval** (not since boot)—host-wide. First tick after start may be **0**. |

Host metrics are typically gathered via **`gopsutil`** or equivalent OS APIs.

**Formatting example (informative):**

```text
[L] INFO [STATS] uptime=1h2m3s mem_avail_mb=1024 mem_total_mb=16384 mem_used_pct=42 cpu_pct=12.3 load1=0.45 load5=0.52 load15=0.48 disk_dbpath_avail_mb=50000 disk_dbpath_total_mb=512000 net_rx_bytes_delta=1250000 net_tx_bytes_delta=890000
```

Exact key names and units are implementation-defined; keep **stable** enough for scripts.

---

## Interaction with `-logtarget` and `-logfilepath`

- Stats lines are **normal log records**; they follow the same sinks as other **Info** lines (file-only, stderr+remote, etc., per the **configuration matrix** in `logtarget-spec.md` if applicable).
- **No separate** “stats-only” sink unless explicitly added later.

---

## Failure and performance

- Collection must be **cheap** (< tens of ms per tick); avoid blocking the **hot path**. Run sampling in a **dedicated goroutine** with a **timer** (`time.Ticker`).
- If OS metrics fail (permission, unsupported OS), log **once** at **Warn** with `[STATS]` or without—prefer **one** diagnostic, then omit failed fields until next restart.

---

## Future extensions (optional)

- **`logstats=off`** in config file to override YAML.
- **JSON**-only stats line for machine parsing (`[STATS]` + JSON blob).
- **Per-subsystem** toggles (memory only, CPU only).
