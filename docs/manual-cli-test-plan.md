# Manual CLI Test Plan

This plan covers the full `cmd/diode` CLI surface, including daemon-by-default behavior, multi-wallet access checks, file transfer, and the hidden/internal command paths that are exercised indirectly.

## Scope

Public commands covered:

- top-level `--help`
- `version`
- `config`
- `query`
- `time`
- `fetch`
- `publish`
- `gateway`
- `socksd`
- `files`
- `push`
- `pull`
- `ssh`
- `daemon`
- `join`
- `bns`
- `token`
- `reset`
- `update`
- `mcp`

Hidden/internal coverage:

- `ssh-proxy`
- `__daemon__`

## Lab Setup

1. Build the lab and fixture environment:

```bash
./scripts/manual/setup_cli_lab.sh up
source ./.manual/cli-lab/env.sh
```

2. The env file exports:

- `DIODE_OWNER_DB`
- `DIODE_PEER_DB`
- `DIODE_VIEWER_DB`
- `DIODE_OWNER_ADDR`
- `DIODE_PEER_ADDR`
- `DIODE_VIEWER_ADDR`
- `DIODE_OWNER_HTTP_ROOT`
- `DIODE_PEER_HTTP_ROOT`
- `DIODE_OWNER_FILES_ROOT`
- `DIODE_PEER_FILES_ROOT`
- `DIODE_OUTPUT_DIR`

3. The env file also defines wrapper helpers:

- `downer ...`
  Runs owner wallet commands with `-no-daemon`.
- `dpeer ...`
  Runs peer wallet commands with `-no-daemon`.
- `dviewer ...`
  Runs viewer wallet commands with `-no-daemon`.
- `ddaemon ...`
  Runs owner wallet commands with daemon mode enabled.
- `dstopdaemon`
  Stops and cleans the global daemon transport files.

4. The lab also starts two local HTTP fixtures:

- `http://127.0.0.1:18080/` backed by `owner-public-fixture`
- `http://127.0.0.1:18081/` backed by `peer-public-fixture`

## Execution Rules

- Use `ddaemon` only for daemon coverage and single-wallet daemon-managed runtime tests.
- Use `downer`, `dpeer`, and `dviewer` for multi-wallet tests because the daemon is global per user and cannot safely represent multiple `-dbpath` identities at once.
- Before any daemon section, run `dstopdaemon`.
- When a test starts a long-running command in one terminal, keep that terminal open and run the verification command in a second terminal.
- Record for each test:
  - exact command
  - exit code
  - stdout/stderr
  - whether the daemon state or runtime state changed as expected

## Wallet Roles

- Owner wallet:
  Hosts public/private ports and file listeners.
- Peer wallet:
  Allowed client for private access tests.
- Viewer wallet:
  Unauthorized client for private access tests.

## Baseline Checks

### Top-Level Help

Command:

```bash
./diode --help
./diode publish --help
./diode daemon --help || true
```

Verify:

- help exits `0`
- help does not start the daemon
- help lists the expected public commands

### Version

Command:

```bash
./diode version
```

Verify:

- exits `0`
- prints OS/arch/CPU
- does not require a running daemon

## Config and Identity

### `config`

Commands:

```bash
downer config -list
downer config -set manual_key=manual_value
downer config -list
downer config -delete manual_key
downer config -list
downer config -unsafe -list
```

Verify:

- first `config -list` creates the wallet DB if it does not exist
- output includes `<address>` and the owner address matches `DIODE_OWNER_ADDR`
- `manual_key` appears after `-set`
- `manual_key` disappears after `-delete`
- `-unsafe` prints the private key material only for the current wallet

### `reset`

Prerequisites:

- funded owner wallet on the target network
- operator accepts destructive wallet/fleet change

Commands:

```bash
downer reset
downer reset -experimental
```

Verify:

- deploys a new fleet contract
- prints new fleet address
- persists the fleet into the owner DB
- a second `reset` against an already initialized wallet reports that the client is already initialized

## Read-Only Network Commands

### `query`

Commands:

```bash
downer query -address "$DIODE_OWNER_ADDR"
downer query -address "$DIODE_PEER_ADDR"
```

Verify:

- exits `0`
- prints account type when decodable
- prints one or more device tickets or a clear resolution failure
- device ticket output includes fleet, server, block, and validation status fields

### `time`

Command:

```bash
downer time
```

Verify:

- exits `0`
- prints minimum and maximum blockchain consensus time
- values are plausible and `maximum >= minimum`

## Daemon Lifecycle and Dispatch

### Implicit Daemon Startup

Commands:

```bash
dstopdaemon
ddaemon publish -public 18080:18080
ddaemon daemon status
```

Verify:

- first `publish` autostarts the hidden daemon
- `publish` returns quickly and does not remain attached to the foreground
- `daemon status` shows `Active mode: publish`
- `daemon status` shows the old-style published port map for port `18080`

### Root-Flag Implicit Publish

Commands:

```bash
ddaemon -bind 19090:$DIODE_OWNER_ADDR:18080
ddaemon daemon status
ddaemon -bind 19090:$DIODE_OWNER_ADDR:18080
ddaemon daemon status
```

Verify:

- root-only `-bind` is treated as implicit `publish`
- the first bind adds one bind entry
- the second identical bind does not duplicate
- `daemon status` still shows the existing `-public 18080:18080` published port table

### `daemon status`

Command:

```bash
ddaemon daemon status
```

Verify:

- shows PID and socket path
- shows active mode and mode args
- shows published port map and bind map when configured
- reports SOCKS/API state correctly

### `daemon restart`

Commands:

```bash
ddaemon daemon restart
ddaemon daemon status
```

Verify:

- exits `0`
- daemon comes back within the timeout
- active mode and published ports survive restart

### `daemon ports remove`

Commands:

```bash
ddaemon daemon ports remove 18080
ddaemon daemon status
```

Verify:

- removes only the requested published port
- leaves unrelated binds intact
- if no published ports remain, mode is stopped cleanly

### `daemon ports clear`

Commands:

```bash
ddaemon publish -public 18080:18080
ddaemon daemon ports clear
ddaemon daemon status
```

Verify:

- clears published ports
- stops the active publish/files mode
- `daemon status` returns `Active mode: none`

### `daemon stop`

Commands:

```bash
ddaemon daemon stop
ddaemon daemon status
```

Verify:

- stop exits `0`
- subsequent `daemon status` reports `not running`

## Publish, Fetch, and Multi-Wallet Access

### Public Publish

Terminal A:

```bash
dstopdaemon
ddaemon publish -public 18080:18080
```

Terminal B:

```bash
dpeer fetch -url "http://$DIODE_OWNER_ADDR.diode.link:18080/" -output "$DIODE_OUTPUT_DIR/public-owner.html"
cat "$DIODE_OUTPUT_DIR/public-owner.html"
```

Verify:

- `publish` prints the old-style port map
- `fetch` exits `0`
- downloaded body contains `owner-public-fixture`

### Private Publish With Allowlist

Terminal A:

```bash
ddaemon publish -private "18081:18081,$DIODE_PEER_ADDR"
```

Terminal B:

```bash
dpeer fetch -url "http://$DIODE_OWNER_ADDR.diode.link:18081/" -output "$DIODE_OUTPUT_DIR/private-peer.html"
cat "$DIODE_OUTPUT_DIR/private-peer.html"
```

Terminal C:

```bash
dviewer fetch -url "http://$DIODE_OWNER_ADDR.diode.link:18081/" -output "$DIODE_OUTPUT_DIR/private-viewer.html"
```

Verify:

- peer wallet succeeds and sees `peer-public-fixture` only if owner fixture on `18081` is running
- viewer wallet fails with a clear access error or connection failure
- `daemon status` shows the allowlisted private port

Note:

- if you want a dedicated private-only fixture on `18081`, start one manually:

```bash
python3 -m http.server 18081 --bind 127.0.0.1 --directory "$DIODE_PEER_HTTP_ROOT"
```

### `fetch`

Commands:

```bash
dpeer fetch -url "http://$DIODE_OWNER_ADDR.diode.link:18080/health.json" -output "$DIODE_OUTPUT_DIR/health.json"
dpeer fetch -method GET -header "accept: application/json" -url "http://$DIODE_OWNER_ADDR.diode.link:18080/health.json" -output "$DIODE_OUTPUT_DIR/health-header.json"
```

Verify:

- both commands exit `0`
- output files exist
- response body matches the hosted JSON fixture

## Files, Push, and Pull

### `files`

Terminal A:

```bash
dstopdaemon
ddaemon files -fileroot "$DIODE_OWNER_FILES_ROOT" 18180
```

Terminal B:

```bash
dpeer pull "$DIODE_OWNER_ADDR:18180:missing.txt" "$DIODE_OUTPUT_DIR/missing.txt"
```

Verify:

- `files` prints the file port banner
- missing file pull fails with a non-2xx error

### `push`

Command:

```bash
dpeer push "$DIODE_SAMPLE_UPLOAD" "$DIODE_OWNER_ADDR:18180:uploads/sample-upload.txt"
```

Verify:

- exits `0`
- owner filesystem now contains `$DIODE_OWNER_FILES_ROOT/uploads/sample-upload.txt`
- file content matches `manual-upload-payload`

### `pull`

Command:

```bash
dviewer pull "$DIODE_OWNER_ADDR:18180:uploads/sample-upload.txt" "$DIODE_OUTPUT_DIR/pulled-upload.txt"
cat "$DIODE_OUTPUT_DIR/pulled-upload.txt"
```

Verify:

- exits `0`
- downloaded file exists
- downloaded content matches the uploaded content

## Proxy and Gateway Modes

### `socksd`

Terminal A:

```bash
downer publish -public 18080:18080
```

Terminal B:

```bash
dpeer socksd -socksd_host 127.0.0.1 -socksd_port 19082
```

Terminal C:

```bash
curl --socks5-hostname 127.0.0.1:19082 "http://$DIODE_OWNER_ADDR.diode.link:18080/"
```

Verify:

- SOCKS listener binds to `127.0.0.1:19082`
- curl returns `owner-public-fixture`
- stopping `socksd` tears down the listener cleanly

### `gateway`

Terminal A:

```bash
downer publish -public 18080:18080
```

Terminal B:

```bash
dpeer gateway -httpd_host 127.0.0.1 -httpd_port 19080
```

Terminal C:

```bash
curl -H "Host: $DIODE_OWNER_ADDR.diode.link:18080" http://127.0.0.1:19080/
```

Verify:

- gateway listener binds to `127.0.0.1:19080`
- response body is the owner fixture
- with `-secure` and valid certs, HTTPS listener also starts and serves the same destination

## SSH

Prerequisites:

- OpenSSH `ssh` and `ssh-keygen` installed on the client machine
- owner machine has a local UNIX account to expose via `-sshd`

Terminal A:

```bash
dstopdaemon
ddaemon publish -sshd "public:2222:$USER"
```

Terminal B:

```bash
dpeer ssh "$USER@$DIODE_OWNER_ADDR.diode" -p 2222
```

Verify:

- `ssh` prints the local/daemon proxy address it is using
- the connection launches the system `ssh` client
- login succeeds or reaches normal SSH host key / auth prompts
- `ps` or SSH verbose output shows the hidden `ssh-proxy` path is being used

Hidden coverage:

- `ssh-proxy` is considered covered when `diode ssh` succeeds through its ProxyCommand path

## Blockchain Write Commands

### `token`

Prerequisites:

- funded owner wallet

Commands:

```bash
downer token -balance
downer token -to "$DIODE_PEER_ADDR" -value 1wei -gasprice 1gwei
dpeer token -balance
```

Verify:

- balance command exits `0` and prints the wallet balance
- transfer command submits successfully
- peer balance or state changes after confirmation

### `bns`

Prerequisites:

- funded owner wallet
- unique BNS name available for testing

Commands:

```bash
downer bns -lookup your-test-name
downer bns -register "your-test-name=$DIODE_OWNER_ADDR"
dviewer bns -lookup your-test-name
downer bns -account your-test-name
downer bns -transfer "your-test-name=$DIODE_PEER_ADDR"
downer bns -unregister your-test-name
```

Verify:

- lookup returns owner and mapped address after registration
- account lookup returns nonce, code, and balance data
- transfer updates the reported owner
- unregister removes the mapping

### `reset`

This is already covered above under Config and Identity because it mutates fleet identity.

## Join

Prerequisites:

- valid perimeter contract address
- any required Oasis local or remote environment variables for the selected `-network`
- if WireGuard coverage is required, local WireGuard tooling and permissions

Commands:

```bash
downer join -dry <perimeter-address>
downer join -network mainnet <perimeter-address>
downer join -network testnet <perimeter-address>
downer join -wireguard -dry <perimeter-address>
```

Verify:

- `-dry` validates and prints contract-derived state without starting the daemon loop
- normal join starts the long-lived reconcile loop
- contract-driven published ports, binds, SOCKS, and WireGuard state are applied
- switching away from `join` by running `ddaemon publish ...` stops the join mode cleanly

## MCP

Prerequisites:

- MCP inspector or another stdio MCP client available

Suggested command:

```bash
./diode -update=false mcp
```

Verify with your MCP client:

- server starts on stdio and stays attached
- tool list includes version, client info, query address, file push/pull, and deploy tools when enabled
- `-mcp-preset=minimal` reduces the exposed tool set
- `-mcp-tool=...` or the corresponding env var filters tools as expected

## Update

Prerequisites:

- use an official release build, not a local `development` binary, for a meaningful update test

Commands:

```bash
./diode update
ddaemon update
```

Verify:

- standalone update either reports `No updates` or installs a newer release and restarts
- daemon-routed update returns the update output to the CLI
- after daemon update, `ddaemon daemon status` works again and the daemon resumes the previous active mode

## Internal Command Coverage

### `__daemon__`

Do not invoke directly in normal manual testing.

Verify indirectly through:

- daemon autostart from `ddaemon publish ...`
- `daemon status`
- `daemon restart`
- daemon metadata/socket presence

### `ssh-proxy`

Do not invoke directly in normal manual testing.

Verify indirectly through:

- successful `diode ssh ...`
- ProxyCommand execution in SSH verbose logs

## Cleanup

Commands:

```bash
dstopdaemon
./scripts/manual/setup_cli_lab.sh down
```

Verify:

- daemon is stopped
- fixture HTTP servers are stopped
- no unexpected long-running `diode` test processes remain
