# Diode MCP specification

Normative description of **`diode mcp`**: Model Context Protocol server over **stdio** (JSON-RPC on stdin/stdout), matching the current client implementation.

---

## Server

| Field | Value |
|-------|--------|
| **Command** | `diode mcp` (with normal global Diode flags and config as for other subcommands). Optional **tool filters** reduce how many tools are registered (see **Tool selection** below). |
| **Transport** | Stdio: MCP messages on **stdin** / **stdout**; implementation logging may use **stderr** (see SDK `LoggingTransport`). |
| **Implementation `name`** | `diode` |
| **Implementation `title`** | `Diode Network Client` |
| **`version`** | Same as the `diode` binary build (reported by **`diode_get_version`**). |

**Server instructions** (exposed to hosts such as Cursor): tools cover client version, local identity on the network, address resolution, file **push**/**pull** to a remote **`diode files`** listener, and **`diode_deploy`** for tarball ingest to a Diode deploy host. **`diode_deploy`** includes a short preview of the remote **`/{uuid}.log`** when available; **`diode_file_pull`** (included in the **`deploy`** preset) fetches the full log or larger bodies. **`diode_deploy`** requires **`DIODE_MCP_DEPLOY_TARGET`** and **`package_path`**; optional **`DIODE_MCP_DEPLOY_UUID`** fixes the deploy token per project (see **`diode_deploy`** below).

**Runtime:** The process runs **`prepareDiode`**, starts the shared **`app`** (Diode client connected to the fleet), then serves MCP until **SIGINT** / **SIGTERM**. **`EnableUpdate`** is disabled for the MCP command. Tools that need the network return an error if there is **no connected client** (`GetNearestClient() == nil`).

### Tool selection

If **none** of the following are set, **every** tool in **Tools** is registered (backward compatible default).

If **any** of the following are set, the active set is the **union** of all specified names (duplicates ignored):

| Mechanism | Example |
|-----------|---------|
| **`-mcp-preset`** | `minimal`, `chain`, `files`, `deploy`, `all` (alias `full`) |
| **Environment `DIODE_MCP_TOOLS`** | Comma-separated tool names (same as **`-mcp-tools`**) |
| **`-mcp-tools`** | Comma-separated tool names |
| **`-mcp-tool`** | Repeat per tool (e.g. `-mcp-tool=diode_deploy -mcp-tool=diode_get_version`) |

**Presets:**

| Preset | Tools included |
|--------|----------------|
| **`minimal`** | `diode_get_version`, `diode_get_client_info` |
| **`chain`** | **`minimal`** + `diode_query_address` |
| **`files`** | **`minimal`** + `diode_file_push`, `diode_file_pull` |
| **`deploy`** | **`minimal`** + `diode_deploy`, `diode_file_pull` |
| **`all`** / **`full`** | All tools |

Unknown preset or unknown tool name → process exits with an error before serving.

---

## Tools

**Tool IDs** (for **`-mcp-tool`**, **`-mcp-tools`**, **`DIODE_MCP_TOOLS`**): `diode_get_version`, `diode_get_client_info`, `diode_query_address`, `diode_file_push`, `diode_file_pull`, `diode_deploy`.

Each tool has a **name** (below), a **description** (as registered with the host), and a **JSON object** input schema inferred from the Go types (property names match the **`json`** tags). Successful structured results are returned as JSON objects with the output field names listed.

### `diode_get_version`

| | |
|--|--|
| **Description** | Return the Diode client binary version and build timestamp. |
| **Input** | Empty object (no parameters). |
| **Result** | `version` (string), `build_time` (string, optional). |
| **Errors** | None from validation; always returns the embedded build metadata. |

---

### `diode_get_client_info`

| | |
|--|--|
| **Description** | Return this client's address, fleet, optional BNS name, and last validated block from the Diode network. |
| **Input** | Empty object. |
| **Result** | `client_address`, `fleet_address`, `last_valid_block`, `last_valid_block_hash` (strings / numbers as encoded); `client_name` (optional, BNS-style **`name.diode`** when configured). |
| **Errors** | Config not initialized; not connected to the Diode network. |

---

### `diode_query_address`

| | |
|--|--|
| **Description** | Resolve a Diode address or name: account type when the input decodes as an address, and device tickets from the network. |
| **Input** | `address` (string, required) - hex address, BNS-style identifier, or other form accepted by **`ResolveDevice`**. |
| **Result** | `address` (echo), optional `account_type` or `account_type_error`; `devices` (array of device ticket objects). Each device object includes fields such as `device_id`, `version`, `server_id`, `block_number`, `block_hash`, `fleet_addr`, `total_connections`, `total_bytes`, `local_addr`, `device_sig`, `server_sig`, `chain_id`, `epoch`, `cache_time`, and optional `validation_error`. |
| **Partial failure** | If resolution fails, `resolve_error` may be set and `devices` may be empty; the tool still returns a structured result when the resolver returns an error (no fatal tool error in that path). |
| **Errors** | Missing `address`; not connected to the Diode network. |

---

### `diode_file_push`

| | |
|--|--|
| **Description** | Upload bytes to a remote HTTP file listener (**`diode files`** contract): **HTTP PUT** to **`http://{peer_host}:{port}{remote_path}`** over the Diode client’s in-process SOCKS dial (same family as **`diode fetch`**). |
| **Input** | `peer_host` (string), `port` (integer 1-65535), `remote_path` (string; leading **`/`** added if missing; path segments URL-escaped). Exactly **one** of: `content_base64` (standard base64) or `local_file_path` (read file from the MCP host filesystem). |
| **Result** | `status_code` (HTTP status), `message` (status line or short response body snippet on failure). |
| **HTTP** | **PUT**, **`Content-Type: application/octet-stream`**, **`Content-Length`** set; client timeout **5 minutes**. |
| **Errors** | Not connected; both or neither of `content_base64` / `local_file_path`; invalid base64 or unreadable local file; bad host/port/path; transport or network failure. Non-2xx HTTP still returns structured output with `status_code` and `message` (up to ~4 KiB of body text when present). |

---

### `diode_file_pull`

| | |
|--|--|
| **Description** | Download a file from a remote HTTP file listener: **HTTP GET** over the same Diode dial path as **`diode_file_push`**. |
| **Input** | `peer_host`, `port`, `remote_path` (same rules as push). Optional `local_path`; optional `max_inline_bytes` (default **4194304** = 4 MiB). |
| **Result** | `status_code`; on success either `content_base64` + `message` (**inline** mode) or `local_path_written` + `message` (**file** mode). |
| **Inline mode** | If `local_path` is omitted: read the response body into memory; if size **>** `max_inline_bytes`, return an error instructing the caller to set `local_path`. Otherwise return **`content_base64`** of the body. |
| **File mode** | If `local_path` is set: resolve destination path - trailing **`/`** or **`\`** or an **existing directory** → write **`basename(remote_path)`** inside that directory; otherwise treat `local_path` as the full output file path (non-existent path → new file). Create parent directories with **`0750`** as needed, then stream the body to the file (new files **`0600`**). |
| **HTTP** | Client timeout **5 minutes**. |
| **Errors** | Not connected; bad host/port/path; transport failure; non-2xx HTTP (structured like push). Inline mode: body too large for `max_inline_bytes`. |

---

### `diode_deploy`

| | |
|--|--|
| **Description** | Upload a **`.tar.gz`** package to a remote **Diode deploy** ingest **`diode files`** listener. Remote path is always **`PUT /{uuid}.tar.gz`**. **`package_path`** is always required (absolute path to the tarball on the MCP host). |
| **Input** | `package_path` (string, required) — absolute path to the tarball. `deploy_token` (string, optional if **`DIODE_MCP_DEPLOY_UUID`** is set) — UUID from the user for the target app when the env UUID is **not** set; **required** in that case. If **`DIODE_MCP_DEPLOY_UUID`** is set, `deploy_token` must **match** the env UUID or be **omitted**. |
| **Environment** | **`DIODE_MCP_DEPLOY_TARGET`** (required): **`diode://<host>:<port>`** (same host forms as **`diode_file_push`**). **`DIODE_MCP_DEPLOY_UUID`** (optional): UUID for this MCP/project; when set, it is the deploy token and the tool **renames** the file at `package_path` to **`{UUID}.tar.gz`** in the same directory if needed (or copies then deletes the source if **rename** crosses devices). If **`{UUID}.tar.gz`** already exists in that directory, the tool errors. When unset, the agent must pass **`deploy_token`** and the tarball must **already** be named **`{deploy_token}.tar.gz`**. |
| **HTTP** | **PUT** to **`http://{host}:{port}/{uuid}.tar.gz`**, **`Content-Type: application/gzip`**, timeout **15 minutes**. After the **PUT** completes (any HTTP status), the tool performs **`GET /{uuid}.log`** on the same listener, retrying on **404** a few times so a just-written log can appear. |
| **Result** | `status_code`, `message`, `remote_path`, `local_path` (path after any rename). Non-2xx **PUT** still returns structured output with a body snippet when present (same style as **`diode_file_push`**). **Log preview fields** (when the log **GET** runs): `log_peer_host`, `log_port`, `log_remote_path` (for **`diode_file_pull`**), `log_status_code`, `log_content` (up to **2 MiB**), `log_truncated` (**true** if larger), `log_message` (status line or note, e.g. **404** if still missing after retries). |
| **Errors** | Not connected; missing **`package_path`**; **`DIODE_MCP_DEPLOY_TARGET`** unset or invalid; missing **`deploy_token`** when **`DIODE_MCP_DEPLOY_UUID`** unset; **`deploy_token`** mismatch with env; invalid UUID; basename wrong when env UUID unset; rename target exists; unreadable package file; transport or network failure on **PUT**. Log **GET** failures are reported in **`log_*`** fields and do not fail the tool unless **PUT** itself failed earlier with a transport error. |
| **Deployment log (remote)** | The **Diode deploy** app (server side) is expected to write **`{uuid}.log`** in its **`diode files`** **`-fileroot`**. Use **`log_content`** from **`diode_deploy`** first; for the full file, **`log_truncated`**, or a higher size limit, call **`diode_file_pull`** with **`log_peer_host`**, **`log_port`**, and **`log_remote_path`**. The **`deploy`** preset registers **`diode_file_pull`** for this. The log may appear only after processing; **404** on **GET** is retried briefly, then surfaced in **`log_message`**. |

---

## Related documents

- **`docs/file-transfer-spec.md`** - normative **`diode files`** / **push** / **pull** HTTP semantics (MCP file tools target that listener).

---

## Status

Tracks **`diode mcp`** and tools under **`cmd/diode/mcp.go`** and **`cmd/diode/internal/mcptools/`**. Update this document when adding or changing tools.
