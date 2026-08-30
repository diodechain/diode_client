// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
//
// forwarded_header.go injects standard proxy forwarding headers (X-Forwarded-For,
// X-Real-IP, Forwarded) so the backend can identify the original client. Behavior
// follows common practice (Nginx, Apache, Cloudflare, RFC 7239).

package rpc

import (
	"bytes"
	"net"
	"strings"
	"sync"
)

// HTTP method prefixes that indicate an HTTP/1.x request line (for detection).
var http1RequestPrefixes = []string{"GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "CONNECT ", "OPTIONS ", "PATCH ", "TRACE "}

// forwardedHeaderConn wraps a connection and injects X-Forwarded-For, X-Real-IP,
// and Forwarded headers into the first HTTP/1.x request, then passes through.
// Implements net.Conn; only Read is special-cased.
type forwardedHeaderConn struct {
	net.Conn
	clientAddr string // IP (or "ip:port") of the connecting client
	mu         sync.Mutex
	buf        bytes.Buffer
	done       bool
}

// newForwardedHeaderConn returns a connection that injects forwarding headers
// into the first HTTP/1.x request. clientAddr should be the address of the
// peer (e.g. conn.RemoteAddr().String()); the IP part is used for headers.
func newForwardedHeaderConn(conn net.Conn, clientAddr string) *forwardedHeaderConn {
	return &forwardedHeaderConn{Conn: conn, clientAddr: clientAddr}
}

// clientIP returns the IP portion of the client address for use in headers.
func clientIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return strings.TrimSpace(host)
}

// injectForwardedHeaders parses the first HTTP request line and headers (up to
// \r\n\r\n), adds or appends X-Forwarded-For, X-Real-IP, and Forwarded, and
// returns the modified request block and any overflow (body) bytes.
func injectForwardedHeaders(raw []byte, clientAddr string) (modified []byte, overflow []byte, ok bool) {
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	if idx < 0 {
		return nil, raw, false
	}
	headerBlock := raw[:idx+4]
	overflow = raw[idx+4:]

	// Only modify if it looks like HTTP/1.x request
	firstLineEnd := bytes.IndexByte(headerBlock, '\n')
	if firstLineEnd <= 0 {
		return nil, raw, false
	}
	firstLine := bytes.TrimSpace(headerBlock[:firstLineEnd])
	reqStr := string(firstLine)
	isHTTP1 := false
	for _, p := range http1RequestPrefixes {
		if strings.HasPrefix(reqStr, p) {
			isHTTP1 = true
			break
		}
	}
	if !isHTTP1 && !strings.HasPrefix(reqStr, "HTTP/1.") {
		return nil, raw, false
	}

	ip := clientIP(clientAddr)
	if ip == "" {
		return nil, raw, false
	}

	// Parse existing headers (simple line-by-line)
	headerLines := bytes.Split(headerBlock[:idx], []byte("\r\n"))
	if len(headerLines) < 1 {
		return nil, raw, false
	}
	requestLine := headerLines[0]
	var newLines [][]byte
	newLines = append(newLines, requestLine)

	var xForwardedFor string
	var hasXRealIP bool
	var hasForwarded bool
	for i := 1; i < len(headerLines); i++ {
		line := headerLines[i]
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			newLines = append(newLines, line)
			continue
		}
		name := strings.TrimSpace(string(bytes.ToLower(line[:colon])))
		value := strings.TrimSpace(string(line[colon+1:]))
		switch name {
		case "x-forwarded-for":
			xForwardedFor = value
			// Don't re-add here; we'll add one line at the end
			continue
		case "x-real-ip":
			hasXRealIP = true
			// Replace with our client
			newLines = append(newLines, []byte("X-Real-IP: "+ip))
			continue
		case "forwarded":
			hasForwarded = true
			// Append our for= (RFC 7239 allows multiple or comma-separated)
			newLines = append(newLines, []byte("Forwarded: "+value+", for=\""+ip+"\";proto=https"))
			continue
		}
		newLines = append(newLines, line)
	}

	// Append X-Forwarded-For (industry standard: append connecting client)
	if xForwardedFor != "" {
		xForwardedFor = xForwardedFor + ", " + ip
	} else {
		xForwardedFor = ip
	}
	newLines = append(newLines, []byte("X-Forwarded-For: "+xForwardedFor))

	if !hasXRealIP {
		newLines = append(newLines, []byte("X-Real-IP: "+ip))
	}
	if !hasForwarded {
		newLines = append(newLines, []byte("Forwarded: for=\""+ip+"\";proto=https"))
	}

	modified = bytes.Join(newLines, []byte("\r\n"))
	modified = append(modified, []byte("\r\n")...)
	return modified, overflow, true
}

// Read implements net.Conn. On first read, consumes an HTTP/1.x request,
// injects forwarding headers, and returns the modified data; later reads
// pass through (including any buffered body).
func (c *forwardedHeaderConn) Read(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.buf.Len() > 0 {
		return c.buf.Read(p)
	}
	if c.done {
		return c.Conn.Read(p)
	}

	// Read until we have \r\n\r\n or a reasonable cap
	var block []byte
	maxLen := 64 * 1024
	for len(block) < maxLen {
		b := make([]byte, 1024)
		nn, readErr := c.Conn.Read(b)
		if nn > 0 {
			block = append(block, b[:nn]...)
			if bytes.Contains(block, []byte("\r\n\r\n")) {
				break
			}
		}
		if readErr != nil {
			if len(block) > 0 {
				c.buf.Write(block)
				c.done = true
				return c.buf.Read(p)
			}
			return 0, readErr
		}
		if nn == 0 {
			break
		}
	}

	if !bytes.Contains(block, []byte("\r\n\r\n")) {
		c.buf.Write(block)
		c.done = true
		return c.buf.Read(p)
	}

	modified, overflow, ok := injectForwardedHeaders(block, c.clientAddr)
	if !ok {
		c.buf.Write(block)
		c.done = true
		return c.buf.Read(p)
	}
	c.done = true
	c.buf.Write(modified)
	if len(overflow) > 0 {
		c.buf.Write(overflow)
	}
	return c.buf.Read(p)
}

func (c *forwardedHeaderConn) Write(p []byte) (n int, err error) {
	return c.Conn.Write(p)
}

// Ensure we implement net.Conn (Read/Write); other methods use embedded Conn.
var _ net.Conn = (*forwardedHeaderConn)(nil)
