package docker

import (
	"testing"
)

func Test_stripDockerMetaFromCommand(t *testing.T) {
	type args struct {
		command string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "empty",
			args: args{
				command: "",
			},
			want: "",
		},
		{
			name: "space strip",
			args: args{
				command: "    space strip   ",
			},
			want: "space strip",
		},
		{
			name: "no strip",
			args: args{
				command: "bin/sh #(nop) CMD [/bin/bash]",
			},
			want: "bin/sh #(nop) CMD [/bin/bash]",
		},
		{
			name: "strip with #(nop)",
			args: args{
				command: "/bin/sh -c #(nop)           CMD [/bin/bash]      ",
			},
			want: "CMD [/bin/bash]",
		},
		{
			name: "strip without #(nop)",
			args: args{
				command: "/bin/sh -c         CMD [/bin/bash]      ",
			},
			want: "CMD [/bin/bash]",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripDockerMetaFromCommand(tt.args.command); got != tt.want {
				t.Errorf("stripDockerMetaFromCommand() = %v, want %v", got, tt.want)
			}
		})
	}
}
