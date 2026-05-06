//go:build !windows

package rpc

import (
	"reflect"
	"testing"
)

func TestNormalizeSupplementaryGroups(t *testing.T) {
	groups, err := normalizeSupplementaryGroups([]string{"100", "200", "100", "300"}, 100)
	if err != nil {
		t.Fatalf("normalizeSupplementaryGroups(): %v", err)
	}
	want := []uint32{200, 300}
	if !reflect.DeepEqual(groups, want) {
		t.Fatalf("normalizeSupplementaryGroups() = %v, want %v", groups, want)
	}
}

func TestNormalizeSupplementaryGroupsRejectsInvalidIDs(t *testing.T) {
	if _, err := normalizeSupplementaryGroups([]string{"not-a-gid"}, 100); err == nil {
		t.Fatalf("expected invalid gid to fail")
	}
}
