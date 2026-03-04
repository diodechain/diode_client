package rpc

import "testing"

func TestNormalizeHostPortPlainHostPort(t *testing.T) {
	got := normalizeHostPort("eu1.prenet.diode.io:41046")
	if got != "eu1.prenet.diode.io:41046" {
		t.Fatalf("expected plain host:port to remain unchanged, got %q", got)
	}
}

func TestNormalizeHostPortFromDiodeURL(t *testing.T) {
	got := normalizeHostPort("diode://0x937c492a77ae90de971986d003ffbc5f8bb2232c@eu1.prenet.diode.io:41046")
	if got != "eu1.prenet.diode.io:41046" {
		t.Fatalf("expected diode URL to normalize to host:port, got %q", got)
	}
}

func TestNormalizeHostPortFromHTTPSURL(t *testing.T) {
	got := normalizeHostPort("HTTPS://Example.COM:443")
	if got != "example.com:443" {
		t.Fatalf("expected HTTPS URL to normalize to lowercase host:port, got %q", got)
	}
}
