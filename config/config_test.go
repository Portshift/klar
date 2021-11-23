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

func Test_validateThresholdSeverity(t *testing.T) {
	type args struct {
		severity string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "Unknown",
			args:    args{
				severity: "Unknown",
			},
			wantErr: false,
		},
		{
			name:    "Negligible",
			args:    args{
				severity: "Negligible",
			},
			wantErr: false,
		},
		{
			name:    "Low",
			args:    args{
				severity: "Low",
			},
			wantErr: false,
		},
		{
			name:    "Medium",
			args:    args{
				severity: "Medium",
			},
			wantErr: false,
		},{
			name:    "High",
			args:    args{
				severity: "High",
			},
			wantErr: false,
		},{
			name:    "Critical",
			args:    args{
				severity: "Critical",
			},
			wantErr: false,
		},{
			name:    "Defcon1",
			args:    args{
				severity: "Defcon1",
			},
			wantErr: false,
		},{
			name:    "Invalid",
			args:    args{
				severity: "Invalid",
			},
			wantErr: true,
		},

	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateThresholdSeverity(tt.args.severity); (err != nil) != tt.wantErr {
				t.Errorf("validateThresholdSeverity() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}