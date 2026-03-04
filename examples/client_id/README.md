# Client ID

A minimal web app that shows the **verified Diode client ID** of the connecting user in the browser. Use it behind a published port so remote Diode clients see their device identity.

## Build

```bash
go build -o client_id ./examples/client_id
```

## Run

1. **Start the diode client** with a published port and the config API enabled. Use global flags for the API:

   ```bash
   diode -api=true -apiaddr=localhost:1081 publish -public 8080:8080
   ```

2. **Start the app** on the same port you published (here 8080):

   ```bash
   ./client_id -port 8080
   ```

   Options:

   - `-port 8080` — listen port (must match the published port's target, e.g. 8080)
   - `-api http://localhost:1081` — Diode config API base URL

3. **Connect as a remote client** through the Diode network (e.g. via `diode connect` or your app) to the publisher's address and port 8080. Open the URL in a browser; the page will show **Your Diode client ID:** followed by the verified device address (e.g. `0x1234...abcd`).

## Flow

- The app gets the TCP peer address from each request (`req.RemoteAddr`).
- It calls the diode config API: `GET /connection-client-id?peer=<addr>`.
- The diode client maps that peer address to the remote Diode device ID and returns it.
- The app renders the client ID in HTML so the user sees it in the browser.

You can use the same pattern in your own web app: call `/connection-client-id?peer=<req.RemoteAddr>` and use the returned `clientId` to load or save per-client settings.
