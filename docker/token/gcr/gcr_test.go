package gcr

import (
	"github.com/containers/image/v5/docker/reference"
	"testing"
)

func TestGCR_IsSupported(t *testing.T) {
	matchNamed, _ := reference.ParseNormalizedNamed("gcr.io/test/test:test")
	noMatchNamed, _ := reference.ParseNormalizedNamed("674200998650.dkr.ecr.eu-central-1.amazonaws.com/test/test:test")
	type args struct {
		named reference.Named
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "match",
			args: args{
				named: matchNamed,
			},
			want: true,
		},
		{
			name: "not match",
			args: args{
				named: noMatchNamed,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &GCR{}
			if got := g.IsSupported(tt.args.named); got != tt.want {
				t.Errorf("IsSupported() = %v, want %v", got, tt.want)
			}
		})
	}
}