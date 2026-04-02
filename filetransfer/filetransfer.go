// Diode Network Client
// Copyright 2025 Diode
// Licensed under the Diode License, Version 1.1

// Package filetransfer implements the HTTP PUT/GET file listener used by diode files,
// diode push/pull, and MCP file tools (see docs/file-transfer-spec.md).
package filetransfer

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// DefaultMaxBody is the default maximum PUT body size (256 MiB).
const DefaultMaxBody int64 = 256 << 20

// Handler serves PUT (upload) and GET/HEAD (download) for a single root policy.
type Handler struct {
	// Fileroot is the absolute directory URL paths are resolved under (no ".." escape).
	Fileroot string
	// MaxBody limits PUT body size (DefaultMaxBody if zero).
	MaxBody int64
}

// ResolveFileroot turns a CLI -fileroot into an absolute path for the listener.
// Empty fileroot means the process current working directory at listen time.
// Use fileroot "/" (or the platform filesystem root) to map URL paths as absolute paths from disk root.
func ResolveFileroot(fileroot string) (string, error) {
	fileroot = strings.TrimSpace(fileroot)
	if fileroot == "" {
		return os.Getwd()
	}
	return filepath.Abs(fileroot)
}

// NewHandler returns an http.Handler for the file transfer HTTP API.
// fileroot is passed through ResolveFileroot (empty → cwd).
func NewHandler(fileroot string) (http.Handler, error) {
	root, err := ResolveFileroot(fileroot)
	if err != nil {
		return nil, err
	}
	return &Handler{Fileroot: root, MaxBody: DefaultMaxBody}, nil
}

func (h *Handler) maxBody() int64 {
	if h.MaxBody <= 0 {
		return DefaultMaxBody
	}
	return h.MaxBody
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		h.servePut(w, r)
	case http.MethodGet:
		h.serveGet(w, r, true)
	case http.MethodHead:
		h.serveGet(w, r, false)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Handler) mapURLPathToFile(urlPath string) (string, error) {
	p := strings.TrimSpace(urlPath)
	if p == "" {
		p = "/"
	}
	raw, err := url.PathUnescape(p)
	if err != nil {
		return "", err
	}

	rootAbs := h.Fileroot
	rel := strings.TrimPrefix(raw, "/")
	rel = filepath.FromSlash(rel)
	clean := filepath.Clean(rel)
	if clean == "." {
		return "", fmt.Errorf("empty path")
	}
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid path")
	}
	full := filepath.Join(rootAbs, clean)
	fullAbs, err := filepath.Abs(full)
	if err != nil {
		return "", err
	}
	rootResolved, err := filepath.Abs(rootAbs)
	if err != nil {
		return "", err
	}
	if !hasPathPrefix(fullAbs, rootResolved) {
		return "", fmt.Errorf("path escapes fileroot")
	}
	return fullAbs, nil
}

func hasPathPrefix(path, prefix string) bool {
	pa, err1 := filepath.Abs(path)
	pb, err2 := filepath.Abs(prefix)
	if err1 != nil || err2 != nil {
		return false
	}
	rel, err := filepath.Rel(pb, pa)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func (h *Handler) servePut(w http.ResponseWriter, r *http.Request) {
	abs, err := h.mapURLPathToFile(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	dir := filepath.Dir(abs)
	if err := os.MkdirAll(dir, 0755); err != nil {
		http.Error(w, "could not create parent directories", http.StatusInternalServerError)
		return
	}

	body := http.MaxBytesReader(w, r.Body, h.maxBody())
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		http.Error(w, "could not open file for write", http.StatusInternalServerError)
		return
	}
	_, copyErr := io.Copy(f, body)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(abs)
		http.Error(w, "write failed", http.StatusInternalServerError)
		return
	}
	if closeErr != nil {
		http.Error(w, "close failed", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) serveGet(w http.ResponseWriter, r *http.Request, withBody bool) {
	abs, err := h.mapURLPathToFile(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	st, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "stat failed", http.StatusInternalServerError)
		return
	}
	if st.IsDir() {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(abs)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	if withBody {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", st.Size()))
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, f)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", st.Size()))
		w.WriteHeader(http.StatusOK)
	}
}
