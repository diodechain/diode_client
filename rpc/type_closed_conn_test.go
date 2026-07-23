package rpc

import (
	"errors"
	"io"
	"net"
	"testing"
)

func TestIsClosedNetworkConnError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "EOF", err: io.EOF, want: false},
		{name: "net.ErrClosed", err: net.ErrClosed, want: true},
		{name: "wrapped ErrClosed", err: errors.Join(errors.New("read"), net.ErrClosed), want: true},
		{name: "phrase", err: errors.New("read udp 127.0.0.1:1: use of closed network connection"), want: true},
		{name: "other", err: errors.New("connection refused"), want: false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := isClosedNetworkConnError(tt.err); got != tt.want {
				t.Fatalf("isClosedNetworkConnError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
