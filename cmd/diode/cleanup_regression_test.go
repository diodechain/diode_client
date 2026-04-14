package main

import (
	"os"
	"strings"
	"testing"
)

func TestCleanupRemovedLegacyControlHelpers(t *testing.T) {
	t.Helper()

	checkAbsent := func(path string, patterns []string) {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", path, err)
		}
		text := string(data)
		for _, pattern := range patterns {
			if strings.Contains(text, pattern) {
				t.Fatalf("expected %s to stay removed from %s", pattern, path)
			}
		}
	}

	checkAbsent("join.go", []string{
		"func updatePortsFromContract(",
		"func updateSSHServicesFromContract(",
		"func buildPublishedPortMap(",
		"func applyConfigKey(",
	})
	checkAbsent("publish.go", []string{
		"func parsePortsEx(",
	})
	checkAbsent("ssh_rules.go", []string{
		"func parseSSHServicesWithClient(",
	})
}
