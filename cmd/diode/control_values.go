package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/diodechain/diode_client/config"
)

// normalizeList trims whitespace, drops empties, and keeps order.
func normalizeList(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func stringFromValue(val interface{}) (string, error) {
	switch v := val.(type) {
	case string:
		return strings.TrimSpace(v), nil
	case fmt.Stringer:
		return strings.TrimSpace(v.String()), nil
	default:
		return strings.TrimSpace(fmt.Sprint(v)), nil
	}
}

func stringSliceFromValue(val interface{}) ([]string, error) {
	switch v := val.(type) {
	case nil:
		return nil, nil
	case string:
		s := strings.TrimSpace(v)
		if s == "" {
			return nil, nil
		}
		// Allow JSON-style arrays, e.g. ["bind1","bind2"].
		if strings.HasPrefix(s, "[") {
			var strItems []string
			if err := json.Unmarshal([]byte(s), &strItems); err == nil {
				return normalizeList(strItems), nil
			}
			var genericItems []interface{}
			if err := json.Unmarshal([]byte(s), &genericItems); err == nil {
				items := make([]string, 0, len(genericItems))
				for _, item := range genericItems {
					items = append(items, fmt.Sprint(item))
				}
				return normalizeList(items), nil
			}
		}
		// Fallback format: split on any whitespace and commas so contract-side
		// concatenation using spaces produces multiple logical entries.
		fields := strings.Fields(s)
		parts := make([]string, 0, len(fields))
		for _, f := range fields {
			parts = append(parts, strings.Split(f, ",")...)
		}
		return normalizeList(parts), nil
	case []interface{}:
		items := make([]string, 0, len(v))
		for _, item := range v {
			items = append(items, fmt.Sprint(item))
		}
		return normalizeList(items), nil
	case []string:
		return normalizeList(v), nil
	case config.StringValues:
		return normalizeList(v), nil
	default:
		return nil, fmt.Errorf("unsupported list type %T", val)
	}
}

func boolFromValue(val interface{}) (bool, error) {
	switch v := val.(type) {
	case bool:
		return v, nil
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes", "y", "on", "t":
			return true, nil
		case "0", "false", "no", "n", "off", "f":
			return false, nil
		case "":
			return false, fmt.Errorf("empty bool string")
		default:
			return false, fmt.Errorf("invalid bool value: %s", v)
		}
	case float64:
		return v != 0, nil
	case int:
		return v != 0, nil
	default:
		return false, fmt.Errorf("unsupported bool type %T", val)
	}
}

func durationFromValue(val interface{}) (time.Duration, error) {
	switch v := val.(type) {
	case string:
		return time.ParseDuration(strings.TrimSpace(v))
	case float64:
		return time.Duration(v) * time.Second, nil
	case int:
		return time.Duration(v) * time.Second, nil
	default:
		return 0, fmt.Errorf("unsupported duration type %T", val)
	}
}

func intFromValue(val interface{}) (int, error) {
	switch v := val.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return 0, fmt.Errorf("empty int value")
		}
		return strconv.Atoi(strings.TrimSpace(v))
	case float64:
		return int(v), nil
	case int:
		return v, nil
	default:
		return 0, fmt.Errorf("unsupported int type %T", val)
	}
}
