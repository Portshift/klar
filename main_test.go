package main

import (
	"reflect"
	"testing"

	grype_models "github.com/anchore/grype/grype/presenter/models"

	vulutils "github.com/Portshift/klar/utils/vulnerability"
)

func Test_filterVulnerabilities1(t *testing.T) {
	type args struct {
		severityThresholdStr string
		vulnerabilities      *grype_models.Document
	}
	tests := []struct {
		name string
		args args
		want *grype_models.Document
	}{
		{
			name: "below threshold",
			args: args{
				severityThresholdStr: vulutils.MediumVulnerability,
				vulnerabilities: &grype_models.Document{
					Matches: []grype_models.Match{
						{
							Vulnerability: grype_models.Vulnerability{
								VulnerabilityMetadata: grype_models.VulnerabilityMetadata{
									Severity: vulutils.LowVulnerability,
								},
							},
						},
					},
				},
			},
			want: &grype_models.Document{
				Matches: nil,
			},
		},
		{
			name: "exact threshold",
			args: args{
				severityThresholdStr: vulutils.MediumVulnerability,
				vulnerabilities: &grype_models.Document{
					Matches: []grype_models.Match{
						{
							Vulnerability: grype_models.Vulnerability{
								VulnerabilityMetadata: grype_models.VulnerabilityMetadata{
									Severity: vulutils.MediumVulnerability,
								},
							},
						},
					},
				},
			},
			want: &grype_models.Document{
				Matches: []grype_models.Match{
					{
						Vulnerability: grype_models.Vulnerability{
							VulnerabilityMetadata: grype_models.VulnerabilityMetadata{
								Severity: vulutils.MediumVulnerability,
							},
						},
					},
				},
			},
		},
		{
			name: "above threshold",
			args: args{
				severityThresholdStr: vulutils.MediumVulnerability,
				vulnerabilities: &grype_models.Document{
					Matches: []grype_models.Match{
						{
							Vulnerability: grype_models.Vulnerability{
								VulnerabilityMetadata: grype_models.VulnerabilityMetadata{
									Severity: vulutils.HighVulnerability,
								},
							},
						},
					},
				},
			},
			want: &grype_models.Document{
				Matches: []grype_models.Match{
					{
						Vulnerability: grype_models.Vulnerability{
							VulnerabilityMetadata: grype_models.VulnerabilityMetadata{
								Severity: vulutils.HighVulnerability,
							},
						},
					},
				},
			},
		},
		{
			name: "mix",
			args: args{
				severityThresholdStr: vulutils.MediumVulnerability,
				vulnerabilities: &grype_models.Document{
					Matches: []grype_models.Match{
						{
							Vulnerability: grype_models.Vulnerability{
								VulnerabilityMetadata: grype_models.VulnerabilityMetadata{
									Severity: vulutils.HighVulnerability,
								},
							},
						},
						{
							Vulnerability: grype_models.Vulnerability{
								VulnerabilityMetadata: grype_models.VulnerabilityMetadata{
									Severity: vulutils.MediumVulnerability,
								},
							},
						},
						{
							Vulnerability: grype_models.Vulnerability{
								VulnerabilityMetadata: grype_models.VulnerabilityMetadata{
									Severity: vulutils.LowVulnerability,
								},
							},
						},
					},
				},
			},
			want: &grype_models.Document{
				Matches: []grype_models.Match{
					{
						Vulnerability: grype_models.Vulnerability{
							VulnerabilityMetadata: grype_models.VulnerabilityMetadata{
								Severity: vulutils.HighVulnerability,
							},
						},
					},
					{
						Vulnerability: grype_models.Vulnerability{
							VulnerabilityMetadata: grype_models.VulnerabilityMetadata{
								Severity: vulutils.MediumVulnerability,
							},
						},
					},
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
