// Diode Network Client
// Copyright 2021 Diode
// Licensed under the Diode License, Version 1.1

package config

import (
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

const defaultTerminalCols = 80

// logLinePrefixReserve is subtracted from the terminal width so label/value
// fits on one line after the logger level prefix (e.g. "INFO ").
const logLinePrefixReserve = 10

// TerminalWidth returns stdout column count, or defaultCols when unavailable.
func TerminalWidth(defaultCols int) int {
	if defaultCols <= 0 {
		defaultCols = defaultTerminalCols
	}
	w, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w < 20 {
		return defaultCols
	}
	return w
}

// TruncateConfigValue shortens value so a PrintLabel line fits termWidth columns.
// When full is true, value is returned unchanged. label must match the key passed
// to PrintLabel so the prefix length matches the formatted line.
func TruncateConfigValue(label, value string, termWidth int, full bool) string {
	if full {
		return value
	}
	tw := termWidth - logLinePrefixReserve
	if tw < 24 {
		tw = 24
	}
	prefix := fmt.Sprintf("%-20s : ", label)
	prefixRunes := utf8.RuneCountInString(prefix)
	maxValRunes := tw - prefixRunes
	if maxValRunes < 4 {
		maxValRunes = 4
	}
	runes := []rune(value)
	if len(runes) <= maxValRunes {
		return value
	}
	if maxValRunes <= 3 {
		return strings.Repeat(".", maxValRunes)
	}
	return string(runes[:maxValRunes-3]) + "..."
}
