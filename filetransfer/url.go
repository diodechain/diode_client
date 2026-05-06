// Diode Network Client
// Copyright 2025 Diode
// Licensed under the Diode License, Version 1.1
package filetransfer

import (
	"fmt"
	"net/url"
	"strings"
)

// EscapeURLPath encodes each segment of a logical path for use in an HTTP URL path.
func EscapeURLPath(remotePath string) string {
	p := strings.Trim(remotePath, "/\\")
	if p == "" {
		return "/"
	}
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return "/" + strings.Join(segs, "/")
}

// BuildHTTPURL returns an http:// URL for a Diode dial (same as diode fetch / file tools).
func BuildHTTPURL(peerHost string, port int, remotePath string) (string, error) {
	if strings.TrimSpace(peerHost) == "" {
		return "", fmt.Errorf("peer host is required")
	}
	if port <= 0 || port > 65535 {
		return "", fmt.Errorf("port must be between 1 and 65535")
	}
	u := url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", peerHost, port),
		Path:   EscapeURLPath(remotePath),
	}
	return u.String(), nil
}
