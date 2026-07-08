// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1
package rpc

import (
	"errors"
	"fmt"
	"testing"
)

func TestIsFastFailDialError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("connection refused"), true},
		{fmt.Errorf("dial tcp: connection refused"), true},
		{errors.New("no route to host"), true},
		{errors.New("network is unreachable"), true},
		{errors.New("i/o timeout"), false},
		{errors.New("connection reset by peer"), false},
	}
	for _, tc := range cases {
		if got := isFastFailDialError(tc.err); got != tc.want {
			t.Errorf("isFastFailDialError(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
