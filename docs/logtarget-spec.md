# `-logtarget` specification

Normative description of the proposed **`diode -logtarget=<clientaddress>:<diodeport>`** flag: ship client logs to a remote Diode identity and port over the tunnel, using an ephemeral local bind and a log sink to the assigned localhost port.

This document is a **design spec**; behavior matches intent here once implemented.

---

## Summary

| Item | Value |
|------|--------|
| **Flag** | `-logtarget=<clientaddress>:<diodeport>` — `<clientaddress>` is **hex address or BNS name** (required; see **Flag syntax**). |
| **Semantics** | Equivalent in effect to `-bind 0:<clientaddress>:<diodeport>:(tcp\|tls)` (protocol TBD and documented), then writing logs to **`127.0.0.1:<assigned_local_port>`** (or the loopback endpoint the stack uses after bind resolution). |
| **Stderr** | **Only** when `-logtarget` is set **and** `-logfilepath` is **not** set: **stderr** keeps the full stream (same as default logging). If `-logfilepath` **is** set, **stderr is not used** for application logs—**same as today** (file-only). See **Stderr and `-logtarget`** and **Configuration matrix**. |
| **Coexistence with `-logfilepath`** | **Option A (tee):** if both are set, emit the **same** encoded log stream to **file** and **remote** only (no stderr; matches current `-logfilepath` behavior). |
| **Bind failure** | **Retry** on initial failure; if still failing, **degrade** (no startup failure, no deadlock); optional background retry to attach remote leg later. |
| **Remote leg backpressure** | **Async + bounded queue + drop when full** (see **Remote log delivery**): slow collectors must not stall the process; **lines may be lost** on the remote sink. |
| **No listener on remote** | If the bind cannot complete a connection to the collector (nothing listening on `<diodeport>`, connection refused, etc.), **do not** spam logs on every retry; **emit at most one status line every 60 seconds** (see **No remote listener**). |

### Configuration matrix (normative)

| `-logfilepath` | `-logtarget` | Application log sinks |
|----------------|--------------|------------------------|
| no | no | **stderr** only (today). |
| no | yes | **stderr** + **remote** (`-logtarget` adds remote; stderr unchanged vs no `-logtarget`). |
| yes | no | **File** only, **no stderr** (today: `config.NewLogger` / `LogMode` file path). |
| yes | yes | **File** + **remote**; **no stderr** (same stderr rule as file-only today). |

---

## Flag syntax

- **Format:** `-logtarget=<clientaddress>:<diodeport>`
- **`<clientaddress>`:** Target device **must** be specifiable either as a **hex Diode address** (same rules as **`-bind`**) or as a **BNS name** (blockchain name service). BNS must resolve once the client and resolvers are available, using the same resolution path as binds and other features that accept BNS. If a name cannot be resolved when the log-target bind is established, treat that like any other bind failure (retry / degrade per **Bind retry and degraded mode**). Flag help text must state that both forms are supported.
- **`<diodeport>`:** Remote port on that device where a log collector listens (same port namespace as other Diode binds).
- **Invalid values:** Reject at startup with a clear error (do not silently ignore).

---

## Behavioral requirements

### Tunnel and bind

- Use the same bind machinery as **`-bind`**: local port **`0`** (OS-assigned), remote **`<clientaddress>:<diodeport>`**, protocol **`tcp`** or **`tls`** per product decision (must be consistent with how collectors are deployed).
- After the bind is active, the implementation must know the **assigned local port** (same discovery path as existing binds: logs / API / startup summary as applicable).

### Bind retry and degraded mode

- If the bind / tunnel **cannot be established on the first attempt**, the implementation **must retry** (bounded backoff or a small fixed number of attempts—exact policy is implementation-defined but must be documented). **Startup must not block indefinitely** waiting for the log-target bind.
- If the bind still fails after retries, **degrade gracefully:** continue normal client startup using **non-remote** sinks only (stderr and/or `-logfilepath` if set). Do **not** fail process startup solely because `-logtarget` could not be satisfied; do **not** deadlock.
- **Continue retrying in the background** after startup so the remote log leg can attach later without restarting the process; log a clear **warn** when operating in degraded mode.

### No remote listener (connect refused / unreachable collector)

Applies when the tunnel or bind is **otherwise viable** but the **TCP/TLS connection to the remote log endpoint cannot be completed**—for example **no process is listening** on `<diodeport>` on the target device (connection refused), or the equivalent failure after the local `localhost:<assigned>` path is ready.

- **Do not** emit an error or warning on **every** failed dial, reconnect attempt, or failed write to the remote leg; that would flood logs and drown out real signal.
- **Do** emit a **status** message on a **fixed 60-second cadence** (at most **once per 60 seconds** per this condition), at **Info** or **Warn**, stating that log shipping to `-logtarget` is **not connected** / **waiting for a listener** (wording implementation-defined). Include enough context to identify the target (address, port) without repeating identical lines more often than this interval.
- **Continue** background retry/reconnect per **Bind retry and degraded mode** and **Remote log delivery**; sinks configured per **Configuration matrix** are unaffected (e.g. file and/or stderr as applicable).
- When the connection **succeeds**, a single **Info** should note that remote log shipping is active again; avoid repeating that on every transient blip.

### Encoding

- Same encoder and level rules as the rest of the process logger (aligned with `config.NewLogger` / `newZapLogger` behavior: level, `logdatetime`, etc.).

### Remote log delivery (normative — async, bounded, drop on pressure)

The **remote** sink (`-logtarget`) **must not** block application goroutines on network I/O. Implement **async + bounded queue + drop**:

**Scope:** “Producer” and “consumer” are **both on the log sender** (the Diode client process)— typically **two goroutines**: one or more **producers** (whatever runs after zap encodes the line, often on the caller’s goroutine) **enqueue** into the buffer; one **consumer** goroutine **dequeues** and performs blocking I/O to `localhost:<assigned>` and the tunnel.

1. **Producer path (hot path):** Encoded log bytes (or records) are **non-blocking** handoff to a **bounded** buffer (e.g. `chan []byte` with fixed capacity, or a ring buffer with the same effect).
2. **Consumer path:** A **dedicated goroutine** reads from that buffer and **writes** to the TCP/TLS connection to `localhost:<assigned>` (through the tunnel).
3. **When the buffer is full:** **Drop** incoming log payloads for the remote leg (e.g. drop newest) - **lossy remote delivery** is explicit.
4. When dropping lines, increment a **dropped-lines** counter and occasionally **warn** (rate-limited) so operators know the collector or tunnel is too slow—recommended.

The **remote** leg is not a file path: encoded output ends in the async pipeline above, then TCP/TLS to the tunnel’s local endpoint.

**Stderr** and **file** legs (when configured) should remain **decoupled** from the remote consumer: a slow or full remote queue **must not** block stderr or file writes. Achieve this with **separate `WriteSyncer`s** or **separate zap cores** so the tee is not a single blocking `MultiWriteSyncer` that includes the async remote enqueue unless stderr/file use non-blocking writers.

### Stderr and `-logtarget`

- **Normative:** If **only** `-logtarget` is set (no `-logfilepath`), **stderr** **must** remain an active sink for the full application log stream—`-logtarget` **adds** remote shipping; it does **not** replace stderr.
- If **`-logfilepath` is also set**, **do not** send application logs to **stderr**; sinks are **file + remote** only, **consistent with today’s file-only logging** (no console copy when logging to a file).
- After the remote leg attaches, do **not** turn off stderr in the “`-logtarget` only” case.

### Bootstrap logging (before the bind is ready)

- Until the client has joined and the bind is established, logging must still be usable for failures (bind error, dial error, etc.).
- Local sink behavior follows **Configuration matrix**: **stderr** when no `-logfilepath`; **file** only when `-logfilepath` is set (today). Once the remote leg is active, the same matrix applies for the **remote** leg.

### After the bind is ready (or while degraded)

- When the bind eventually succeeds, reconfigure or rebuild the logger so the **primary application log** matches **Configuration matrix**:
  - **Remote sink** (tee leg to `localhost:<assigned>`) whenever `-logtarget` is set;
  - **File sink** if `-logfilepath` is set;
  - **Stderr** only in the **no `-logfilepath`** row (see **Stderr and `-logtarget`**).
- While degraded (no remote leg yet), **file** and/or **stderr** per the matrix continue; the remote leg is absent until it attaches.

---

## Coexistence with `-logfilepath` (Option A — tee)

When **both** `-logfilepath=<path>` and `-logtarget=...` are set:

1. **File** + **remote** only (**no stderr** for application logs—same as **`-logfilepath` alone** today). **File** should receive the full stream barring local disk failure; **remote** may **drop** lines per **Remote log delivery**.
2. **Ordering:** No global ordering guarantee between **file** and **remote**; the **remote** leg may omit lines that the **file** still has.
3. **Backpressure:** The **remote** leg uses **async + bounded queue + drop** (see **Remote log delivery**). **File** must not be blocked by a slow remote collector.

When **only** `-logfilepath` is set: unchanged from today (file only, no stderr).

When **only** `-logtarget` is set: **stderr** + **remote** once the bind is ready; if the remote leg is absent or degraded, **stderr** is unchanged.

When **neither** is set: unchanged (stderr per current `LogMode` rules).

---

## Failure modes

| Condition | Expected behavior |
|-----------|---------------------|
| Bind / tunnel cannot be established (initially) | **Retry** the bind (see **Bind retry and degraded mode**). **Do not** deadlock startup. |
| Bind / tunnel still failing after retries | **Degrade:** run with stderr and/or file logging only; emit a clear **warn** that `-logtarget` is inactive. **Do not** abort startup solely for this reason. |
| No listener / connection refused / remote closes and reconnect fails | **Retry** or reconnect with backoff; **at most one status log every 60 seconds** while the remote leg is down (see **No remote listener**); do not log on every attempt. Other sinks per **Configuration matrix** unchanged. |
| Remote closes at runtime then reconnects quickly | Reconnect with backoff; no need for 60s status if recovery is immediate; optional single Info when re-established. |
| File path invalid (existing `-logfilepath` rules) | Preserve current validation; remote leg independent of file open success once tee is implemented (if file fails, policy should be explicit: abort all vs remote-only). |

---

## Operator documentation (user-facing)

- The **collector** must listen on **`<diodeport>`** on the target device; `-logtarget` only configures the **client** side (tunnel + log sink).
- **`<clientaddress>`** may be a **BNS name** or a **hex Diode address**, consistent with `-bind`.
- Operators should see the **assigned local port** in the same bind summary used for other `-bind` entries.
- If nothing is listening on `<diodeport>`, expect a **status message about once per minute** (not a flood of errors) until a collector is available or `-logtarget` is removed.
- **Local stderr** shows the full log stream when `-logtarget` is set **without** `-logfilepath`; if **both** are set, logs go to **file + remote** only (no stderr copy), same as file-only today.

---

## Implementation notes (non-normative)

- Zap’s `OutputPaths` are typically **file paths**; a safe **tee** with a lossy remote leg usually means **two cores** or **two encoders** feeding **file `WriteSyncer`** and **`WriteSyncer` that only enqueues** (non-blocking), not one `MultiWriteSyncer` that includes a blocking socket.
- Queue **depth** (and drop policy) may be **configurable** later; v1 can use fixed constants with documentation.
- **YAML / config file:** mirror flag with a field such as `logtarget` if the rest of the client mirrors global flags in config.

---

## Future extensions (optional)

- **`-logsink=both|file|remote`** — only if product needs to override Option A tee without removing flags.
- **Reconnect policy** knobs for the remote leg.
