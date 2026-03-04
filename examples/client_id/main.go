// client_id is a minimal example web app that shows the connecting Diode client ID
// in the browser. Run it behind a published port (e.g. diode publish -public 8080:8080)
// so remote Diode clients can connect and see their verified device ID.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
)

var (
	port = flag.String("port", "8080", "Listen port for the demo server")
	api  = flag.String("api", "http://localhost:1081", "Diode config API base URL (for /connection-client-id)")
)

func main() {
	flag.Parse()
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/client-id", handleAPIClientID)
	addr := ":" + *port
	log.Printf("client_id listening on %s (diode API: %s)", addr, *api)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatal(err)
	}
}

type clientIDResponse struct {
	ClientID string `json:"clientId"`
}

// handleIndex serves the page immediately so the user sees something right away.
// The page then fetches /api/client-id and updates the DOM when the lookup completes.
func handleIndex(w http.ResponseWriter, req *http.Request) {
	writeHTML(w, http.StatusOK, fmt.Sprintf(`<h1>Connection client ID</h1>
<p id="peer">Peer: <code>%s</code></p>
<p id="status">Resolving your client ID…</p>
<div id="result"></div>
<p id="hint" style="color:#666;font-size:0.9em">(If this stays here for a long time, the delay is in the diode API lookup.)</p>
<script>
(function(){
  var start = performance.now();
  var status = document.getElementById('status');
  var result = document.getElementById('result');
  var hint = document.getElementById('hint');
  fetch('/api/client-id', { headers: { 'Content-Type': 'application/json' } })
    .then(function(r) { return r.json().then(function(d) { return { ok: r.ok, data: d }; }); })
    .then(function(o) {
      var elapsed = (performance.now() - start) / 1000;
      status.textContent = 'Resolved in ' + elapsed.toFixed(2) + 's';
      hint.style.display = 'none';
      if (o.ok && o.data.clientId) {
        result.innerHTML = '<p><strong>Client ID:</strong> <code>' + o.data.clientId + '</code></p><p>Use this verified identity to store or restore per-client settings.</p>';
      } else {
        result.innerHTML = '<p style="color:#c00">Could not resolve: ' + (o.data.error || 'unknown') + '</p><p>Make sure you are connecting through a Diode published port and the diode config API is running (e.g. diode -api=true -apiaddr=localhost:1081 publish -public %s:%s).</p>';
      }
    })
    .catch(function(e) {
      status.textContent = 'Request failed';
      result.innerHTML = '<p style="color:#c00">' + e.message + '</p>';
      hint.style.display = 'none';
    });
})();
</script>`, req.RemoteAddr, *port, *port))
}

// handleAPIClientID returns the client ID for the current connection (uses req.RemoteAddr).
// Called by the index page via fetch so the initial HTML can be sent immediately.
func handleAPIClientID(w http.ResponseWriter, req *http.Request) {
	peer := req.RemoteAddr
	clientID, err := fetchClientID(peer)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusOK)
		if encErr := json.NewEncoder(w).Encode(map[string]string{"error": err.Error(), "peer": peer}); encErr != nil {
			log.Printf("failed to encode error response: %v", encErr)
		}
		return
	}
	if encErr := json.NewEncoder(w).Encode(map[string]string{"clientId": clientID, "peer": peer}); encErr != nil {
		log.Printf("failed to encode client-id response: %v", encErr)
	}
}

func fetchClientID(peerAddr string) (string, error) {
	base := *api
	if base == "" {
		base = "http://localhost:1081"
	}
	u := base + "/connection-client-id?peer=" + url.QueryEscape(peerAddr)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API returned %d: %s", resp.StatusCode, string(body))
	}
	var out clientIDResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.ClientID == "" {
		return "", fmt.Errorf("empty clientId in response")
	}
	return out.ClientID, nil
}

func writeHTML(w http.ResponseWriter, code int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	if _, err := w.Write([]byte("<!DOCTYPE html><html><body>" + body + "</body></html>")); err != nil {
		log.Printf("failed to write HTML response: %v", err)
	}
}
