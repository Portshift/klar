package run

import (
	"github.com/Portshift/klar/config"
	"testing"
)

func Test_setImageSource(t *testing.T) {
	type args struct {
		imageName string
		conf      *config.Config
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "registry image",
			args: args{
				imageName: "test",
				conf: &config.Config{
					IsRegistryImage:      true,
				},
			},
			want: "registry:test",
		},
		{
			name: "docker daemon image",
			args: args{
				imageName: "test",
				conf: &config.Config{
					IsRegistryImage:      false,
				},
			},
			want: "docker:test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := setImageSource(tt.args.imageName, tt.args.conf); got != tt.want {
				t.Errorf("setImageSource() = %v, want %v", got, tt.want)
			}
		})
	}
}
