package config

import (
	"os"
	"testing"
)

func TestParseIntOption(t *testing.T) {
	cases := []struct {
		value    string
		expected int
	}{
		{
			value:    "",
			expected: 0,
		},
		{
			value:    "0",
			expected: 0,
		},
		{
			value:    "10",
			expected: 10,
		},
		{
			value:    "x",
			expected: 0,
		},
	}
	for _, tc := range cases {
		os.Setenv(OptionSeverityThreshold, tc.value)
		if got := parseIntOption(OptionSeverityThreshold); got != tc.expected {
			t.Errorf("expected %d got %d", tc.expected, got)
		}
	}
}

func TestParseBoolOption(t *testing.T) {
	cases := []struct {
		value    string
		expected bool
	}{
		{
			value:    "",
			expected: false,
		},
		{
			value:    "x",
			expected: false,
		},
		{
			value:    "true",
			expected: true,
		},
		{
			value:    "false",
			expected: false,
		},
	}
	for _, tc := range cases {
		os.Setenv(OptionDockerInsecure, tc.value)
		if got := parseBoolOption(OptionDockerInsecure); got != tc.expected {
			t.Errorf("%q: expected %v got %v", tc.value, tc.expected, got)
		}
	}
}
