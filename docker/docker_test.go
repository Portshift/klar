package docker

import (
	"encoding/json"
	"fmt"
	docker_manifest "github.com/containers/image/v5/manifest"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestNewImage(t *testing.T) {
	tcs := map[string]struct {
		image    string
		registry string
		name     string
		tag      string
	}{
		"full": {
			image:    "docker-registry.domain.com:8080/nginx:1b29e1531c",
			registry: "https://docker-registry.domain.com:8080/v2",
			name:     "nginx",
			tag:      "1b29e1531c",
		},
		"regular": {
			image:    "docker-registry.domain.com/nginx:1b29e1531c",
			registry: "https://docker-registry.domain.com/v2",
			name:     "nginx",
			tag:      "1b29e1531c",
		},
		"regular_extended": {
			image:    "docker-registry.domain.com/skynetservices/skydns:2.3",
			registry: "https://docker-registry.domain.com/v2",
			name:     "skynetservices/skydns",
			tag:      "2.3",
		},
		"no_tag": {
			image:    "docker-registry.domain.com/nginx",
			registry: "https://docker-registry.domain.com/v2",
			name:     "nginx",
			tag:      "latest",
		},
		"no_tag_with_port": {
			image:    "docker-registry.domain.com:8080/nginx",
			registry: "https://docker-registry.domain.com:8080/v2",
			name:     "nginx",
			tag:      "latest",
		},

		"no_registry": {
			image:    "skynetservices/skydns:2.3",
			registry: "https://registry-1.docker.io/v2",
			name:     "skynetservices/skydns",
			tag:      "2.3",
		},
		"no_registry_root": {
			image:    "postgres:9.5.1",
			registry: "https://registry-1.docker.io/v2",
			name:     "library/postgres",
			tag:      "9.5.1",
		},
		"digest": {
			image:    "postgres@sha256:f6a2b81d981ace74aeafb2ed2982d52984d82958bfe836b82cbe4bf1ba440999",
			registry: "https://registry-1.docker.io/v2",
			name:     "library/postgres",
			tag:      "sha256:f6a2b81d981ace74aeafb2ed2982d52984d82958bfe836b82cbe4bf1ba440999",
		},
		"digest and tag": {
			image:    "postgres:2.4.1@sha256:f6a2b81d981ace74aeafb2ed2982d52984d82958bfe836b82cbe4bf1ba440999",
			registry: "https://registry-1.docker.io/v2",
			name:     "library/postgres",
			tag:      "sha256:f6a2b81d981ace74aeafb2ed2982d52984d82958bfe836b82cbe4bf1ba440999",
		},
		"localhost_no_tag": {
			image:    "localhost/nginx",
			registry: "https://localhost/v2",
			name:     "nginx",
			tag:      "latest",
		},
		"localhost_tag_with_port": {
			image:    "localhost:8080/nginx:xxx",
			registry: "https://localhost:8080/v2",
			name:     "nginx",
			tag:      "xxx",
		},
	}
	for name, tc := range tcs {

		image, err := NewImage(&Config{ImageName: tc.image})
		if err != nil {
			t.Fatalf("%s: Can't parse image name: %s", name, err)
		}
		if image.Registry != tc.registry {
			t.Fatalf("%s: Expected registry name %s, got %s", name, tc.registry, image.Registry)
		}
		if image.Name != tc.name {
			t.Fatalf("%s: Expected image name %s, got %s", name, tc.name, image.Name)
		}
		if image.Reference != tc.tag {
			t.Fatalf("%s: Expected image tag %s, got %s", name, tc.tag, image.Reference)
		}
	}

}

func TestPullManifestSchemaV1(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/vnd.docker.distribution.manifest.v1+prettyjws")
		resp, err := ioutil.ReadFile("testdata/registry-response.json")
		if err != nil {
			t.Fatalf("Can't load registry test response %s", err.Error())
		}
		fmt.Fprintln(w, string(resp))
	}))
	defer ts.Close()

	image, err := NewImage(&Config{ImageName: "docker-registry.domain.com/nginx:1b29e1531ci"})
	image.Registry = ts.URL
	err = image.Pull()
	if err != nil {
		t.Fatalf("Can't pull image: %s", err)
	}
	if len(image.FsLayers) == 0 {
		t.Fatal("Can't pull fsLayers")
	}
}

func TestPullManifestSchemaV2(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := ioutil.ReadFile("testdata/registry-response-schemav2.json")
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		if err != nil {
			t.Fatalf("Can't load registry test response %s", err.Error())
		}
		fmt.Fprintln(w, string(resp))
	}))
	defer ts.Close()

	image, err := NewImage(&Config{ImageName: "docker-registry.domain.com/nginx:1b29e1531c"})
	image.Registry = ts.URL
	err = image.Pull()
	if err != nil {
		t.Fatalf("Can't pull image: %s", err)
	}
	if len(image.FsLayers) == 0 {
		t.Fatal("Can't pull fsLayers")
	}
}

func Test_extractV1LayersWithCommands(t *testing.T) {
	command1 := docker_manifest.Schema1V1Compatibility{}
	command1.ContainerConfig.Cmd = []string{"command1"}
	command2 := docker_manifest.Schema1V1Compatibility{}
	command2.ContainerConfig.Cmd = []string{"command2"}
	commandPartsToStrip := docker_manifest.Schema1V1Compatibility{}
	commandPartsToStrip.ContainerConfig.Cmd = []string{"/bin/sh", "-c", "#(nop)", "CMD [/bin/bash]"}
	commandToStrip := docker_manifest.Schema1V1Compatibility{}
	commandToStrip.ContainerConfig.Cmd = []string{"/bin/sh -c #(nop)    CMD [/bin/bash]  "}
	type args struct {
		image   *Image
		schema1 *docker_manifest.Schema1
	}
	tests := []struct {
		name string
		args args
		want *Image
	}{
		{
			name: "Empty",
			args: args{
				image: &Image{
					FsLayers:   nil,
					FsCommands: nil,
				},
				schema1: &docker_manifest.Schema1{
					FSLayers:                 nil,
					ExtractedV1Compatibility: nil,
				},
			},
			want: &Image{
				FsLayers:   make([]FsLayer, 0),
				FsCommands: make([]*FsLayerCommand, 0),
			},
		},
		{
			name: "two layers with commands - should be reversed",
			args: args{
				image: &Image{
					FsLayers:   make([]FsLayer, 0),
					FsCommands: make([]*FsLayerCommand, 0),
				},
				schema1: &docker_manifest.Schema1{
					FSLayers:                 []docker_manifest.Schema1FSLayers{
						{
							BlobSum: "sha256:bbb",
						},
						{
							BlobSum: "sha256:aaa",
						},
					},
					ExtractedV1Compatibility: []docker_manifest.Schema1V1Compatibility{
						command2,
						command1,
					},
				},
			},
			want: &Image{
				FsLayers:   []FsLayer{
					{
						BlobSum: "sha256:aaa",
					},
					{
						BlobSum: "sha256:bbb",
					},
				},
				FsCommands: []*FsLayerCommand{
					{
						Command: "command1",
						Layer:   "aaa",
					},
					{
						Command: "command2",
						Layer:   "bbb",
					},
				},
			},
		},
		{
			name: "strip layer command with several parts",
			args: args{
				image: &Image{
					FsLayers:   make([]FsLayer, 0),
					FsCommands: make([]*FsLayerCommand, 0),
				},
				schema1: &docker_manifest.Schema1{
					FSLayers:                 []docker_manifest.Schema1FSLayers{
						{
							BlobSum: "sha256:aaa",
						},
					},
					ExtractedV1Compatibility: []docker_manifest.Schema1V1Compatibility{
						commandPartsToStrip,
					},
				},
			},
			want: &Image{
				FsLayers:   []FsLayer{
					{
						BlobSum: "sha256:aaa",
					},
				},
				FsCommands: []*FsLayerCommand{
					{
						Command: "CMD [/bin/bash]",
						Layer:   "aaa",
					},
				},
			},
		},
		{
			name: "strip layer command",
			args: args{
				image: &Image{
					FsLayers:   make([]FsLayer, 0),
					FsCommands: make([]*FsLayerCommand, 0),
				},
				schema1: &docker_manifest.Schema1{
					FSLayers:                 []docker_manifest.Schema1FSLayers{
						{
							BlobSum: "sha256:aaa",
						},
					},
					ExtractedV1Compatibility: []docker_manifest.Schema1V1Compatibility{
						commandToStrip,
					},
				},
			},
			want: &Image{
				FsLayers:   []FsLayer{
					{
						BlobSum: "sha256:aaa",
					},
				},
				FsCommands: []*FsLayerCommand{
					{
						Command: "CMD [/bin/bash]",
						Layer:   "aaa",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractV1LayersWithCommands(tt.args.image, tt.args.schema1)
			if !reflect.DeepEqual(tt.args.image, tt.want) {
				gotB, _ := json.Marshal(tt.args.image)
				wantB, _ := json.Marshal(tt.want)
				t.Fatalf("extractV1LayersWithCommands()=%s, want=%s", gotB, wantB)
			}
		})
	}
}

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