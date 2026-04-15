# Log target listener

Minimal TCP listener that prints whatever bytes arrive on a port. Use it to receive **`-logtarget`** traffic: remote Diode clients tunnel zap console log bytes to a **host:port** you choose.

## Build

```bash
go build -o logtarget_listener ./examples/logtarget_listener
```

## Topology: publish/listener vs log sources

- **Log sources** (remote) run the Diode client with **`-logtarget=<collector>:<port>`** or **`-logtarget=diode://<collector>:<port>`** (optional `diode://` prefix). Their logs are forwarded over the network to that address and port.
- **Collector** (this example) is the machine that **accepts** those connections. In practice it is often the **same host** that **publishes** a port so inbound Diode traffic hits your process:

  Publish something like **`-public <local>:<extern>`** (or another scope). Remote **`-logtarget`** flows connect to your published **extern** port (the port in the `-logtarget` flag must match **extern**).

So the process that **listens** on `local` is usually co-located with the `diode` that **published** it. The “publisher” in the publish sense is **this** host; the “publishers” in the log-shipping sense are the **remote** clients sending `-logtarget` streams.

## Run (collector / listener)

Bind to the same **port** that appears in **`-logtarget`** (your published **extern**):

```bash
./logtarget_listener -listen 0.0.0.0:9999
```

- `-listen host:port` — must match the `-logtarget` port (e.g. `9999`).

## Run (remote log sources)

On each client that should **ship** logs to you:

```bash
diode -logtarget=diode://0xYourCollectorDevice…:9999 publish -public 80:80
```

(`-logtarget=0xYourCollectorDevice…:9999` is equivalent.) Use the collector’s Diode address and the **same** port your listener uses. After binds come up, log lines appear on the listener’s stdout.

## Resolving which client sent the stream

Raw log bytes do **not** include Diode identity. On the **same machine** as `diode`, the **localhost config API** can map an inbound connection’s **peer** to the **verified Diode client id** (same pattern as the [client_id](../client_id) example: e.g. `GET /connection-client-id?peer=<RemoteAddr>`).

For each accepted connection, take `conn.RemoteAddr()` (in the form your API expects), query the API, and you can **label** or route logs by **source client id**. That works for **many** concurrent `-logtarget` sources: one accepted socket per active stream; **reconnects** close and reopen connections, so look up again when a new connection arrives.

## Notes

- Data is **raw** bytes from the remote logger (console-style lines), not HTTP.
- **Multiple clients** can connect to the same listener port; use the API (or explicit tags inside log lines) if you need to tell streams apart on stdout.
