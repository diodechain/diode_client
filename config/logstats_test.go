package config

import (
	"strings"
	"testing"
)

func TestAppendRuntimeMemIncludesLeakTriageFields(t *testing.T) {
	var b strings.Builder
	appendRuntimeMem(&b)
	got := b.String()
	for _, key := range []string{
		"heap_alloc_mb=",
		"heap_inuse_mb=",
		"heap_sys_mb=",
		"stack_inuse_mb=",
		"goroutines=",
		"num_gc=",
	} {
		if !strings.Contains(got, key) {
			t.Fatalf("runtime mem stats missing %q in %q", key, got)
		}
	}
}

func TestAppendProcessMemIncludesRSS(t *testing.T) {
	var b strings.Builder
	var warned error
	appendProcessMem(&b, func(err error) { warned = err })
	got := b.String()
	if warned != nil && got == "" {
		t.Skipf("process memory unavailable in this environment: %v", warned)
	}
	if !strings.Contains(got, "proc_rss_mb=") {
		t.Fatalf("process mem stats missing proc_rss_mb in %q (warn=%v)", got, warned)
	}
}
