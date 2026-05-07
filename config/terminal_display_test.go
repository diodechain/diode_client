// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1

package config

import "testing"

func TestTruncateConfigValue(t *testing.T) {
	t.Parallel()
	suffix := "the quick brown fox jumps over the lazy dog"
	long := ""
	for len(long) < 200 {
		long += suffix
	}
	tests := []struct {
		name      string
		label     string
		value     string
		termWidth int
		full      bool
		want      string
	}{
		{
			name:      "full flag",
			label:     "relay_candidates_v1",
			value:     long,
			termWidth: 80,
			full:      true,
			want:      long,
		},
		{
			name:      "short unchanged",
			label:     "lvbn3",
			value:     "0xa55f04",
			termWidth: 80,
			full:      false,
			want:      "0xa55f04",
		},
		{
			name:      "truncated",
			label:     "relay_candidates_v1",
			value:     long,
			termWidth: 80,
			full:      false,
			want:      "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := TruncateConfigValue(tt.label, tt.value, tt.termWidth, tt.full)
			if tt.want != "" {
				if got != tt.want {
					t.Fatalf("got %q want %q", got, tt.want)
				}
				return
			}
			if len(got) < 4 {
				t.Fatalf("expected truncated value, got %q", got)
			}
			if got[len(got)-3:] != "..." {
				t.Fatalf("expected ellipsis suffix, got %q", got)
			}
			if len(got) >= len(tt.value) {
				t.Fatalf("expected shorter than input")
			}
		})
	}
}
