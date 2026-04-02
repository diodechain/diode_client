# Diode file transfer specification (`files`, `push`, `pull`)

Normative contract for **`diode files`**, **`publish -files`**, **`diode push`**, and **`diode pull`**: publication shape, path resolution (**`-fileroot`**), CLI forms, and the shared HTTP behavior (listener and gateway).

---

## Serving: `diode files` and `publish -files`

```text
diode [global flags] files [-fileroot <path>] <files-spec>
diode [global flags] publish … -files <files-spec> [-fileroot <path>] …
```

**`diode files` and flags:** The Go **`flag`** parser stops at the first non-flag argument. Put **`-fileroot`** (and any other **`files`** subcommand flags such as **`-socksd`**) **before** **`<files-spec>`**. Otherwise **`-fileroot` is ignored** as a flag token (do not place it after the port); see **Path resolution** for the default when **`-fileroot` is omitted**.

### Examples (serving)

```text
# Public listener on 8080; URL paths relative to process cwd at startup (no -fileroot)
diode files 8080

# Same with explicit root directory
diode files -fileroot /var/inbox 8080

# Same with fleet / registry flags as usual
diode -fleet 0x… files -fileroot /srv/data 8080

# Private listener with allowlist (BNS name and hex address; same rules as publish -private)
diode files -fileroot /inbox 8080,mydevice.diode,0x0000000000000000000000000000000000000001

# Composed with other publish ports and optional socksd
diode publish -public 80:8000 -files 8080 -fileroot /var/inbox -socksd

# Multiple file listeners (repeat -files); one -fileroot applies to all of them
diode publish -files 8080 -files 9090 -fileroot /data -public 443:8443
```

**`-files`** adds this listener **alongside** other **`publish`** ports; must not **port-conflict**. Composes with other **`publish`** / client options (**`-public`** / **`-protected`** / **`-private`**, **`-socksd`**, **`-bind`**, …) per **`publish`** documentation.

**`-fileroot`** without any **`-files`** on **`publish`**: the reference implementation **logs a warning** and ignores **`-fileroot`**.

The listener **MUST** implement **HTTP** as in **HTTP interface** below (**PUT** and **GET** for regular files; **HEAD** optional).

---

## Publication: `files-spec`

Positional argument to **`diode files`** and value of **`publish -files`**:

```text
<port>[,<name-or-0x>[,…]]
```

### Examples (`files-spec`)

```text
8080
8080,mybns.diode,0x1234567890123456789012345678901234567890
```

| Value | Effective publication |
|-------|------------------------|
| `<port>` only (e.g. `8080`) | **Public:** published (**external**) port **`8080`**; **local** TCP bind is an **ephemeral** port chosen by the OS on **`127.0.0.1`** (or **`SrcHost`** if you use an explicit **`host:…`** form in the first segment). Operators do **not** pick the local port. |
| `<port>,…` (e.g. `8080,mybns,0x…`) | **Private:** same local/ephemeral behavior for the bare **`8080`** case, plus allowlist segments after the comma (same grammar as **`publish -private`**). Internally this is **`0:8080,…`** until bind, then **`Src`** is the assigned local port. |

### Explicit local bind (optional)

If you **must** pin the local listener to a specific port (e.g. another tool expects **`localhost:9000`**), use the same **`local:published`** form as **`publish`** in the first segment, e.g. **`9000:8080`** or **`127.0.0.1:9000:8080`**. That disables ephemeral assignment for that listener.

---

## Path resolution: `-fileroot`

Applies to **`push`**, **`pull`**, listener **`PUT`**/**`GET`**, and HTTPS paths the same way.

The URL path (after **`https://host:port`**) is always **`/` + path relative to a directory root** on the listener (percent-encoded per segment); that root is **not** included in the URL.

| | |
|--|--|
| **`-fileroot` omitted** | Root is the listener process **current working directory** at the time the file HTTP server starts (snapshot). **PUT:** create missing parent directories under that root (**`mkdir -p`**). Reject **`..`** that escapes the root. **GET:** same mapping; outside root → **404**. |
| **`-fileroot <root>`** | Root is **`<root>`** (made absolute). Same **PUT**/**GET** rules as above. Use **`-fileroot /`** (POSIX) or the platform filesystem root to map URL paths under **disk root** (e.g. **`PUT /var/log/app.log`** → **`/var/log/app.log`**). |

**HTTPS URL:** Same as HTTP path mapping: **`/` + relative path** under the resolved root.

### Examples (path resolution)

**With `-fileroot /srv/inbox`:**

- Request **`PUT /photos/vacation.jpg`** → file **`/srv/inbox/photos/vacation.jpg`** (create **`photos/`** if needed).
- Request **`GET /photos/vacation.jpg`** → same file.

**Without `-fileroot`**, cwd **`/home/user/project`:**

- Request **`PUT /moo.txt`** → **`/home/user/project/moo.txt`** (parents created as needed).
- Request **`PUT /out/sub/a.txt`** → **`/home/user/project/out/sub/a.txt`**.

**With `-fileroot /` (POSIX):**

- Request **`PUT /var/log/app/line.log`** → **`/var/log/app/line.log`** (parents created as needed).

---

## `diode push`

```text
diode push <local-file> <peer>:<port>
diode push <local-file> <peer>:<port>:<remote-path>
```

### Examples (`push`)

```text
# Remote path = basename(local-file) → e.g. photo.jpg under peer's fileroot
diode push ./photo.jpg mydevice.diode.link:8080

# Explicit remote path under peer's file root
diode push ./photo.jpg mydevice.diode.link:8080:photos/vacation.jpg

# IPv6 peer (brackets required)
diode push ./data.bin '[2001:db8::1]':8080:uploads/data.bin
```

| Form | Destination |
|------|-------------|
| `<peer>:<port>` | Default remote path is the **basename** of **`<local-file>`** under the peer’s resolved file root (cwd or **`-fileroot`** at listener start). |
| `<peer>:<port>:<remote-path>` | Per **Path resolution** above. |

**`<peer>`:** BNS / `*.diode` / implementation-defined. Use **`[ipv6]:port:…`** when colons are ambiguous.

---

## `diode pull`

```text
diode pull <peer>:<port>:<remote-path> [<local-path>]
```

### Examples (`pull`)

```text
# Write to ./vacation.jpg in the current directory
diode pull mydevice.diode.link:8080:photos/vacation.jpg

# Explicit local file path
diode pull mydevice.diode.link:8080:photos/vacation.jpg /tmp/vacation.jpg

# Directory destination (trailing slash) → /var/serve/vacation.jpg
diode pull mydevice.diode.link:8080:photos/vacation.jpg /var/serve/

# IPv6
diode pull '[2001:db8::1]':8080:export/readme.txt ./readme.txt
```

**`<remote-path>`** uses the same rules as **`push`**. **`<peer>`** - same as **`push`**.

**If `<local-path>` is omitted:** write **`basename(<remote-path>)`** in the **current working directory** (document decoding/normalization if non-default).

**If `<local-path>` is present:** interpret as either a **directory** or a **file** destination:

| | Output path |
|--|-------------|
| **Directory** | **`Join(<local-path>, basename(<remote-path>))`** |
| **File** | **Exactly `<local-path>`** |

**Disambiguation (recommended):** trailing **`/`** or **`\`** means directory; an **existing** directory path means directory; if absent and the path does not exist, **MUST** document whether it is created as a directory or as a single file path (trailing separator is the unambiguous form). **Reference implementation:** a non-existent **`local-path`** without a trailing separator is treated as a **file** path (single file created; parent dirs **may** be created).

**Client writes:** Only the **one** output file; parent dirs for that path **MAY** be created (**`mkdir -p`**). If **`<local-path>`** is omitted, **do not** create directories except the file in cwd. Reject **`..`** / escape as documented.

**Remote directory:** **`pull`** is a **single** **`GET`** of a **regular file**. If **`remote-path`** is a directory, **GET** is not a file body → **404** (or equivalent); **no** recursive copy. Directory trees are out of scope unless specified later.

**Alternate form** (optional): **`diode pull <peer>:<port> <remote-path> [<local-path>]`** when peer, port, and remote path cannot be expressed as one colon-delimited argument - **MUST** be documented if supported. **Reference implementation:** not implemented; use quoted **`peer:port:path`** instead.

---

## HTTP interface

**Same handler and status semantics** for the listener, **`diode push`** / **`diode pull`**, HTTPS gateway, and optional small **JSON POST** (if implemented).

### Methods

| Method | Behavior |
|--------|----------|
| **PUT** | Create or replace file at mapped path. |
| **GET** | File bytes; **404** if missing or not a regular file. |
| **HEAD** | Optional; same path as **GET**, no body. |

### Status codes

| Code | Meaning |
|------|---------|
| **2xx** | Success: **200** for **GET** / **HEAD**; **201** or **204** typical for **PUT**. |
| **400** | Bad path, body, or method; bad JSON if JSON profile. |
| **403** | Not allowed (e.g. private listener, not allowlisted). |
| **404** | **GET:** not found / not a file. |
| **413** | **PUT** body too large. |
| **500** | Server or filesystem error. |

Optional **JSON** body on **4xx**/**5xx** - if present, **`push`** / **`pull`** SHOULD surface it or a summary.

### Request and response bodies

| | |
|--|--|
| **Raw** | **PUT:** **`Content-Type: application/octet-stream`**, **`Content-Length`** set. **GET:** body = file bytes. |
| **Optional JSON** | **POST** **`application/json`** (e.g. base64 fields) - small payloads only; field names **MUST** be documented. Large blobs use raw **PUT** / **GET**. |

### Gateway base URL

```text
https://<name>.diode.link:<port>/
```

### Examples (gateway)

```text
https://mydevice.diode.link:8080/photos/vacation.jpg
https://0xabcdef0123456789abcdef0123456789abcdef.diode.link:8080/inbox/note.txt
```

**`<name>`** and **`<port>`** match **`files-spec`**; other hostname forms (e.g. hex) **MUST** be documented where relevant.

### Example (aligned paths)

**`-fileroot /srv/inbox`**, port **8080**, remote file **`photos/vacation.jpg`**:

- **PUT / GET:** `https://mydevice.diode.link:8080/photos/vacation.jpg`
- On disk: **`/srv/inbox/photos/vacation.jpg`** (create **`photos/`** on **PUT** if needed)

**Default root = listener cwd:** **`PUT /moo.txt`** with **`https://…:8080/moo.txt`** writes under the directory the peer was in when **`diode files`** started. To expose paths from disk root, the peer runs with **`-fileroot /`** (POSIX).

### Examples (`curl` over HTTPS gateway)

Same contract as **`diode push`** / **`diode pull`:** **PUT** or **GET**, **`Content-Type: application/octet-stream`** on **PUT**, URL path = **`/` + relative path** under the listener’s resolved root (cwd or **`-fileroot`**), with each path segment encoded like **`filetransfer.EscapeURLPath`** (per-segment percent-encoding; ASCII-only segments can be pasted literally).

**Upload (mimic `diode push`):** path **`/moo.txt`** maps to **`<root>/moo.txt`** where **`<root>`** is **`-fileroot`** or the peer’s cwd when the listener started.

```bash
# Remote path = basename of the local file (same as push with peer:port only).
curl -fS --connect-timeout 30 --max-time 600 \
  -T ./moo.txt -H 'Content-Type: application/octet-stream' \
  'https://mydevice.diode.link:8080/moo.txt'

# Explicit path under -fileroot.
curl -fS --connect-timeout 30 --max-time 600 \
  -T ./note.txt -H 'Content-Type: application/octet-stream' \
  'https://mydevice.diode.link:8080/folder/note.txt'
```

**Download (mimic `diode pull`):**

```bash
curl -fS -o vacation.jpg 'https://mydevice.diode.link:8080/photos/vacation.jpg'
```

**Paths with reserved characters:** build the path with per-segment encoding, e.g. in Python:

```python
"/" + "/".join(urllib.parse.quote(seg, safe="") for seg in remote.split("/"))
```

**Reachability:** if **`curl`** does not resolve **`.diode.link`** from your network, use **`--resolve`**, a local proxy, or **`diode fetch`** with a **`diode://` / `https://…diode.link…`** URL through the Diode client.

---

## Status

Normative specification for the Diode client. **`diode files`**, **`diode push`**, **`diode pull`**, **`publish -files`**, and MCP **`diode_file_push`** / **`diode_file_pull`** share the **`filetransfer`** package (`filetransfer/`).
