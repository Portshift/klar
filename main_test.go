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

//func Test_setKubeRegistryIfNeeded(t *testing.T) {
//	type args struct {
//		imageName string
//	}
//	tests := []struct {
//		name string
//		args args
//		want string
//	}{
//		{
//			name: "not localhost prefix - should not be updated",
//			args: args{
//				imageName: "test",
//			},
//			want: "test",
//		},
//		{
//			name: "with localhost prefix - should be updated",
//			args: args{
//				imageName: "localhost:30000/blabla:tag",
//			},
//			want: "kube-registry.default.svc.cluster.local:30000/blabla:tag",
//		},
//		{
//			name: "with localhost, but not prefix - should not be updated",
//			args: args{
//				imageName: "test/localhost:tag",
//			},
//			want: "test/localhost:tag",
//		},
//	}
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			if got := setKubeRegistryIfNeeded(tt.args.imageName); got != tt.want {
//				t.Errorf("setKubeRegistryIfNeeded() = %v, want %v", got, tt.want)
//			}
//		})
//	}
//}

func Test_setKubeRegistryIfNeeded(t *testing.T) {
	type args struct {
		imageName string
	}
	tests := []struct {
		name  string
		args  args
		want  string
		want1 bool
	}{
		{
			name: "non kube-registry - don't touch",
			args: args{
				imageName: "test.regular/image",
			},
			want:  "test.regular/image",
			want1: false,
		},
		{
			name: "kube-registry on localhost - replace",
			args: args{
				imageName: "localhost:30000/andromeda/epic",
			},
			want:  "100.64.0.9:5000/andromeda/epic",
			want1: true,
		},
		{
			name: "kube-registry on node - don't touch",
			args: args{
				imageName: "100.64.0.9:5000/image",
			},
			want:  "100.64.0.9:5000/image",
			want1: true,
		},
		{
			name: "other localhost - don't touch",
			args: args{
				imageName: "localhost:5000/image",
			},
			want:  "localhost:5000/image",
			want1: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := setKubeRegistryIfNeeded(tt.args.imageName)
			if got != tt.want {
				t.Errorf("setKubeRegistryIfNeeded() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("setKubeRegistryIfNeeded() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}