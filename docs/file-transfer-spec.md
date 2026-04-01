# Diode file transfer specification (`files`, `push`, `pull`)

Normative contract for **`diode files`**, **`publish -files`**, **`diode push`**, and **`diode pull`**: publication shape, path resolution (**`-fileroot`**), CLI forms, and the shared HTTP behavior (listener and gateway).

---

## Publication: `files-spec`

Positional argument to **`diode files`** and value of **`publish -files`**:

```text
<port>[,<name-or-0x>[,…]]
```

| Value | Effective publication |
|-------|------------------------|
| `<port>` only (e.g. `8080`) | `-public <ephemeral>:<port>` |
| `<port>,…` (e.g. `8080,mybns,0x…`) | `-private <ephemeral>:<port>,…` (allowlist per **`publish -private`**) |

---

## Path resolution: `-fileroot`

Applies to **`push`**, **`pull`**, listener **`PUT`**/**`GET`**, and HTTPS paths the same way.

| | |
|--|--|
| **With `-fileroot <root>`** | Paths are **relative to `<root>`** on the listener host. **PUT:** create missing directories under `<root>` (**`mkdir -p`**). Reject **`..`** that escapes `<root>`. **GET:** same mapping; outside `<root>` → **404** or **403** (document which). |
| **Without** | Paths are **absolute** on the listener host. **PUT:** parent directories must already exist. **GET:** read that absolute path. |

**HTTPS URL:** With **`-fileroot`**, the URL path (after **`https://host:port`**) is **`/` + relative path** (percent-encoded); **`<root>`** is not part of the URL. Without **`-fileroot`**, the URL path is the absolute path (percent-encoded).

---

## Serving: `diode files` and `publish -files`

```text
diode [global flags] files <files-spec> [-fileroot <path>]
diode [global flags] publish … -files <files-spec> [-fileroot <path>] …
```

**`-files`** adds this listener **alongside** other **`publish`** ports; must not **port-conflict**. Composes with other **`publish`** / client options (**`-public`** / **`-protected`** / **`-private`**, **`-socksd`**, **`-bind`**, …) per **`publish`** documentation. **`-fileroot`** without **`-files`** - ignore and warn, or error (document which).

The listener **MUST** implement **HTTP** as in **HTTP interface** below (**PUT** and **GET** for regular files; **HEAD** optional).

---

## `diode push`

```text
diode push <local-file> <peer>:<port>
diode push <local-file> <peer>:<port>:<remote-path>
```

| Form | Destination |
|------|-------------|
| `<peer>:<port>` | Only valid when the peer used **`-fileroot`**: default path under `<root>` is **implementation-defined** (e.g. basename of `<local-file>`); **MUST** be documented. |
| `<peer>:<port>:<remote-path>` | Per **Path resolution** above. |

**`<peer>`:** BNS / `*.diode` / implementation-defined. Use **`[ipv6]:port:…`** when colons are ambiguous.

---

## `diode pull`

```text
diode pull <peer>:<port>:<remote-path> [<local-path>]
```

**`<remote-path>`** uses the same rules as **`push`**. **`<peer>`** - same as **`push`**.

**If `<local-path>` is omitted:** write **`basename(<remote-path>)`** in the **current working directory** (document decoding/normalization if non-default).

**If `<local-path>` is present:** interpret as either a **directory** or a **file** destination:

| | Output path |
|--|-------------|
| **Directory** | **`Join(<local-path>, basename(<remote-path>))`** |
| **File** | **Exactly `<local-path>`** |

**Disambiguation (recommended):** trailing **`/`** or **`\`** means directory; an **existing** directory path means directory; if absent and the path does not exist, **MUST** document whether it is created as a directory or as a single file path (trailing separator is the unambiguous form).

**Client writes:** Only the **one** output file; parent dirs for that path **MAY** be created (**`mkdir -p`**). If **`<local-path>`** is omitted, **do not** create directories except the file in cwd. Reject **`..`** / escape as documented.

**Remote directory:** **`pull`** is a **single** **`GET`** of a **regular file**. If **`remote-path`** is a directory, **GET** is not a file body → **404** (or equivalent); **no** recursive copy. Directory trees are out of scope unless specified later.

**Alternate form** (optional): **`diode pull <peer>:<port> <remote-path> [<local-path>]`** when peer, port, and remote path cannot be expressed as one colon-delimited argument - **MUST** be documented if supported.

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
| **404** | **GET:** not found / not a file. **PUT:** parents missing when **`-fileroot`** omitted and creation not allowed. |
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

**`<name>`** and **`<port>`** match **`files-spec`**; other hostname forms (e.g. hex) **MUST** be documented where relevant.

### Example (aligned paths)

**`-fileroot /srv/inbox`**, port **8080**, remote file **`photos/vacation.jpg`**:

- **PUT / GET:** `https://<host>:8080/photos/vacation.jpg`
- On disk: **`/srv/inbox/photos/vacation.jpg`** (create **`photos/`** on **PUT** if needed)

**Without `-fileroot`**, absolute **`/var/log/remote/app.log`** maps to **`https://host:8080/var/log/remote/app.log`**.

---

## Status

Normative specification for the Diode client.
