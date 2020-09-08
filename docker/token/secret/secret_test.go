package secret

import (
	"context"
	"github.com/containers/image/v5/docker/reference"
	"testing"
)

func TestImagePullSecret_GetCredentials(t *testing.T) {
	gcrImage, _ := reference.ParseNormalizedNamed("gcr.io/library/image:123")
	gcrImageSpecific, _ := reference.ParseNormalizedNamed("gcr.io/more/specific:123")
	noMatch, _ := reference.ParseNormalizedNamed("no/match:123")
	imageNoScheme, _ := reference.ParseNormalizedNamed("foo.example.com/image:123")
	imageNoDefaultRegistry, _ := reference.ParseNormalizedNamed("foo")
	type fields struct {
		body string
	}
	type args struct {
		in0   context.Context
		named reference.Named
	}
	tests := []struct {
		name         string
		fields       fields
		args         args
		wantUsername string
		wantPassword string
		wantErr      bool
	}{
		{
			name: "gcr no specific image",
			fields: fields{
				body: "{\"auths\":{\"gcr.io\":{\"username\":\"gcr\",\"password\":\"io\",\"auth\":\"Z2NyOmlv\"},\"gcr.io/more/specific\":{\"username\":\"gcr\",\"password\":\"io/more/specific\",\"auth\":\"Z2NyOmlvL21vcmUvc3BlY2lmaWM=\"},\"http://foo.example.com\":{\"username\":\"foo\",\"password\":\"bar\",\"auth\":\"Zm9vOmJhcg==\"}}}",
			},
			args: args{
				named: gcrImage,
			},
			wantUsername: "gcr",
			wantPassword: "io",
			wantErr:      false,
		},
		{
			name: "gcr specific image",
			fields: fields{
				body: "{\"auths\":{\"gcr.io\":{\"username\":\"gcr\",\"password\":\"io\",\"auth\":\"Z2NyOmlv\"},\"gcr.io/more/specific\":{\"username\":\"gcr\",\"password\":\"io/more/specific\",\"auth\":\"Z2NyOmlvL21vcmUvc3BlY2lmaWM=\"},\"http://foo.example.com\":{\"username\":\"foo\",\"password\":\"bar\",\"auth\":\"Zm9vOmJhcg==\"}}}",
			},
			args: args{
				named: gcrImageSpecific,
			},
			wantUsername: "gcr",
			wantPassword: "io/more/specific",
			wantErr:      false,
		},
		{
			name: "no match",
			fields: fields{
				body: "{\"auths\":{\"gcr.io\":{\"username\":\"gcr\",\"password\":\"io\",\"auth\":\"Z2NyOmlv\"},\"gcr.io/more/specific\":{\"username\":\"gcr\",\"password\":\"io/more/specific\",\"auth\":\"Z2NyOmlvL21vcmUvc3BlY2lmaWM=\"},\"http://foo.example.com\":{\"username\":\"foo\",\"password\":\"bar\",\"auth\":\"Zm9vOmJhcg==\"}}}",
			},
			args: args{
				named: noMatch,
			},
			wantUsername: "",
			wantPassword: "",
			wantErr:      true,
		},
		{
			name: "match registry with scheme",
			fields: fields{
				body: "{\"auths\":{\"gcr.io\":{\"username\":\"gcr\",\"password\":\"io\",\"auth\":\"Z2NyOmlv\"},\"gcr.io/more/specific\":{\"username\":\"gcr\",\"password\":\"io/more/specific\",\"auth\":\"Z2NyOmlvL21vcmUvc3BlY2lmaWM=\"},\"http://foo.example.com\":{\"username\":\"foo\",\"password\":\"bar\",\"auth\":\"Zm9vOmJhcg==\"}}}",
			},
			args: args{
				named: imageNoScheme,
			},
			wantUsername: "foo",
			wantPassword: "bar",
			wantErr:      false,
		},
		{
			name: "match registry no default registry",
			fields: fields{
				body: "{\"auths\":{\"docker.io\":{\"username\":\"docker\",\"password\":\"io\",\"auth\":\"ZG9ja2VyOmlv\"},\"gcr.io/more/specific\":{\"username\":\"gcr\",\"password\":\"io/more/specific\",\"auth\":\"Z2NyOmlvL21vcmUvc3BlY2lmaWM=\"},\"http://foo.example.com\":{\"username\":\"foo\",\"password\":\"bar\",\"auth\":\"Zm9vOmJhcg==\"}}}",
			},
			args: args{
				named: imageNoDefaultRegistry,
			},
			wantUsername: "docker",
			wantPassword: "io",
			wantErr:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &ImagePullSecret{
				body: tt.fields.body,
			}
			gotUsername, gotPassword, err := s.GetCredentials(tt.args.in0, tt.args.named)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetCredentials() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotUsername != tt.wantUsername {
				t.Errorf("GetCredentials() gotUsername = %v, want %v", gotUsername, tt.wantUsername)
			}
			if gotPassword != tt.wantPassword {
				t.Errorf("GetCredentials() gotPassword = %v, want %v", gotPassword, tt.wantPassword)
			}
		})
	}
}

