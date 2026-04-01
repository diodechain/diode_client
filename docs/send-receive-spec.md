# Diode `send` / `receive` specification

Normative reference for **`diode send`**, **`diode receive`**, and **`publish -receive`**: CLI shapes, receive publication (**public** / **private**), inbox paths, HTTP **`PUT`** upload contract, shared responses, and gateway URLs.

---

## CLI model

- **One subcommand per process:** `receive`, `publish`, or `send`.
- **`receive`** — standalone receive-only daemon.
- **`publish … -receive …`** — same receive syntax **as flags**, composed with **`-public` / `-protected` / `-private`**, **`-socksd`**, global **`-bind`**, etc.
- **`send`** — outbound upload to a peer.

---

## `receive-spec` (shared)

Used as the **positional** to **`diode receive`** and as the **value of `-receive`** on **`publish`**:

```text
<port>[,<name-or-0x>[,…]]
```

| Value | Publication | Meaning |
|-------|-------------|---------|
| `<port>` only, e.g. `8080` | `-public <ephemeral>:<port>` | Public receive; local bind is ephemeral, mapped to `<port>` on the network. |
| `<port>,…` e.g. `8080,mybns,0x…` | `-private <ephemeral>:<port>,…` | Private receive; allowlist matches existing **`publish -private`** rules. |

---

## `-receivepath`

| | |
|--|--|
| **With `-receivepath <root>`** | Relative **`send`** / gateway paths resolve under `<root>`. **Create missing directories** under `<root>` before write (**`mkdir -p`** semantics). Reject **`..`** that escapes `<root>`. |
| **Without** | Remote paths must be **absolute** on the receiver; **all parent dirs must already exist** (no auto-create). |

---

## `diode receive` (standalone)

```text
diode [global flags] receive <receive-spec> [-receivepath <path>]
```

```text
diode receive 8080
diode receive 8080 -receivepath /mypath
diode receive 8080,mybns,0x0000000000000000000000000000000000000001 -receivepath /inbox
```

Global **`-bind`** applies to the same client session when documented (same idea as **`socksd`** / **`publish`**).

---

## `publish -receive` (composed)

```text
diode [global flags] publish … -receive <receive-spec> [-receivepath <path>] …
```

Adds this receive publication **alongside** other **`publish`** ports; must not **port-conflict** with them.

```text
diode -bind 0:<remote>:32400 publish -public 80:8000 -receive 8080 -receivepath /mypath -socksd
```

**Parsing:** `-receivepath` without `-receive` → **ignore** and **warn** (or **error**—pick one behavior and document it).

---

## `diode send`

```text
diode send <local-file> <peer>:<port>
diode send <local-file> <peer>:<port>:<remote-path>
```

| Form | Use |
|------|-----|
| `<peer>:<port>` | Default destination in inbox — **only** if peer used **`-receivepath`**. |
| `<peer>:<port>:<remote-path>` | Relative (if peer has **`-receivepath`**) or absolute (if not), per **`-receivepath`** rules above. |

**`<peer>`** — BNS / `*.diode` / implementation-defined. Use **`[ipv6]:port:path`** form when colons are ambiguous.

---

## Upload responses (all entry points)

Same semantics for **`diode send`** (HTTP client inside CLI), **HTTPS gateway**, and **optional JSON POST** (if implemented).

| Code | Meaning |
|------|---------|
| **2xx** | Success (**`201`** / **`204`** typical for **`PUT`**). |
| **400** | Bad path, body, or method; invalid JSON if JSON profile. |
| **403** | Forbidden (e.g. private receive, not allowlisted). |
| **404** | Not found, or parents missing when **`-receivepath` omitted** and creation disallowed. |
| **413** | Payload too large. |
| **500** | Server/filesystem error (recommended for ops/debugging). |

Optional **JSON** error body for **4xx/5xx** (e.g. `{"error":"…","code":"…"}`) — if used, **`diode send`** SHOULD print it or a summary.

---

## HTTPS / gateway

Custom clients (**`curl`**, Python, agents) use the **same** handler and responses as **`diode send`**.

### Base URL

```text
https://<name>.diode.link:<port>/
```

`<name>` and `<port>` match **`receive-spec`** publication; see **`publish`** “HTTP Gateway” output. Document any alternate hostname forms (e.g. hex).

### Path mapping

Must match **`send`** destination path on disk:

| **`-receivepath`** | URL path (after **`https://host:port`**) | On-disk file |
|--------------------|-------------------------------------------|----------------|
| **Set** to `<root>` | **`/` + relative path** (percent-encoded). **Not** including `<root>` in the URL—the server maps relative segments under `<root>`. | `<root>` / relative / file |
| **Omitted** | **Absolute** path as URL path (percent-encoded). | Same absolute path on receiver |

**Example** (`-receivepath /srv/inbox`, port `8080`):

```text
# CLI
diode send ./photo.jpg mydevice.diode:8080:photos/vacation.jpg

# HTTPS (relative URL path = remote path segments)
PUT https://mydevice.diode.link:8080/photos/vacation.jpg
Content-Type: application/octet-stream
```

Receiver writes **`/srv/inbox/photos/vacation.jpg`** (creating **`photos/`** if needed).

**Without `-receivepath`**, absolute CLI path **`/var/log/remote/app.log`** → **`PUT https://host:8080/var/log/remote/app.log`**.

### Encoding

| | |
|--|--|
| **Canonical** | **`PUT`**, body = **raw bytes**, **`Content-Type: application/octet-stream`**, **`Content-Length`** set. |
| **Optional JSON** | **`POST`**, **`application/json`**, e.g. `path` + `content_base64` (RFC 4648) — **small payloads only**; field names MUST be documented. Large files → raw **`PUT`**. |

---

## Agents / deployments

| Pattern | Approach |
|---------|----------|
| **Single artifact** | `tar czf` / `zip`, then **one** `PUT` or **`send`** to e.g. `peer:port:releases/v1.tgz`. **Preferred** for large trees. |
| **Many files** | Multiple **`PUT`**s; **`-receivepath`** auto-creates dirs. **N** round trips. |
| **Tooling** | Raw **`PUT`** + TLS — no Diode SDK required; avoid base64 for large blobs. |

---

## Implementation checklist

- Shared parser for **`receive-spec`** + **`-receivepath`** from **`receive`** and **`publish -receive`**.
- **`receive`**: `app.Start()`, publish port, HTTP server, `app.Wait()` (like **`socksd`**).
- **`publish`**: if **`-receive`**, same listener setup + existing publish/**socksd** lifecycle.
- **`send`**: `app.Start()`, resolve peer, **HTTP `PUT`** (or documented JSON) — **same URL/path rules and response handling** as gateway.
- One upload code path for CLI + HTTPS; **Upload responses** table above.

---

## Status

Spec only; behavior exists when implemented in the client.
