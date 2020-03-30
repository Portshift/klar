package main

import (
	"github.com/Portshift/klar/clair"
	vulutils "github.com/Portshift/klar/utils/vulnerability"
	"reflect"
	"testing"
)

func Test_filterVulnerabilities1(t *testing.T) {
	type args struct {
		severityThresholdStr string
		vulnerabilities      []*clair.Vulnerability
	}
	tests := []struct {
		name string
		args args
		want []*clair.Vulnerability
	}{
		{
			name: "below threshold",
			args: args{
				severityThresholdStr:       vulutils.MediumVulnerability,
				vulnerabilities: []*clair.Vulnerability{
					{
						Severity:       vulutils.LowVulnerability,
					},
				},
			},
			want: nil,
		},
		{
			name: "exact threshold",
			args: args{
				severityThresholdStr:       vulutils.MediumVulnerability,
				vulnerabilities: []*clair.Vulnerability{
					{
						Severity:       vulutils.MediumVulnerability,
					},
				},
			},
			want: []*clair.Vulnerability{
				{
					Severity: vulutils.MediumVulnerability,
				},
			},
		},
		{
			name: "above threshold",
			args: args{
				severityThresholdStr:       vulutils.MediumVulnerability,
				vulnerabilities: []*clair.Vulnerability{
					{
						Severity:       vulutils.HighVulnerability,
					},
				},
			},
			want: []*clair.Vulnerability{
				{
					Severity: vulutils.HighVulnerability,
				},
			},
		},
		{
			name: "mix",
			args: args{
				severityThresholdStr:       vulutils.MediumVulnerability,
				vulnerabilities: []*clair.Vulnerability{
					{
						Severity:       vulutils.LowVulnerability,
					},
					{
						Severity:       vulutils.MediumVulnerability,
					},
					{
						Severity:       vulutils.HighVulnerability,
					},
				},
			},
			want: []*clair.Vulnerability{
				{
					Severity:       vulutils.MediumVulnerability,
				},
				{
					Severity:       vulutils.HighVulnerability,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := filterVulnerabilities(tt.args.severityThresholdStr, tt.args.vulnerabilities); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("filterVulnerabilities() = %v, want %v", got, tt.want)
			}
		})
	}
}