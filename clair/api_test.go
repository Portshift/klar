package clair

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
)

func TestNewAPIV1(t *testing.T) {
	cases := []struct {
		url      string
		expected string
	}{
		{
			url:      "http://localhost:6060",
			expected: "http://localhost:6060",
		},
		{
			url:      "http://localhost",
			expected: "http://localhost:6060",
		},
		{
			url:      "localhost",
			expected: "http://localhost:6060",
		},
		{
			url:      "https://localhost:6060",
			expected: "https://localhost:6060",
		},
		{
			url:      "https://localhost",
			expected: "https://localhost:6060",
		},
	}
	for _, tc := range cases {
		api := newAPIV1(tc.url, time.Minute)
		if api.url != tc.expected {
			t.Errorf("expected %s got %s", api.url, tc.expected)
		}
	}
}

func Test_apiV1_sendWithRetries(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()

	mockHTTPClient := NewMockHTTPClient(mockCtrl)

	type fields struct {
		url    string
		client HTTPClient
	}
	type args struct {
		request *http.Request
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		expect func(client *MockHTTPClient)
		want    *http.Response
		wantErr bool
	}{
		{
			name:    "success on first try",
			fields:  fields{
				client: mockHTTPClient,
			},
			args:    args{
				request: nil,
			},
			expect: func(client *MockHTTPClient) {
				client.EXPECT().Do(gomock.Any()).Return(&http.Response{
					Status:           "ok",
				}, nil)
			},
			want:    &http.Response{
				Status: "ok",
			},
			wantErr: false,
		},
		{
			name:    "success on second try",
			fields:  fields{
				client: mockHTTPClient,
			},
			args:    args{
				request: nil,
			},
			expect: func(client *MockHTTPClient) {
				client.EXPECT().Do(gomock.Any()).Return(nil, fmt.Errorf("fail"))
				client.EXPECT().Do(gomock.Any()).Return(&http.Response{
					Status:           "ok",
				}, nil)
			},
			want:    &http.Response{
				Status: "ok",
			},
			wantErr: false,
		},
		{
			name:    "fail after max retries",
			fields:  fields{
				client: mockHTTPClient,
			},
			args:    args{
				request: nil,
			},
			expect: func(client *MockHTTPClient) {
				client.EXPECT().Do(gomock.Any()).Return(nil, fmt.Errorf("fail"))
				client.EXPECT().Do(gomock.Any()).Return(nil, fmt.Errorf("fail"))
				client.EXPECT().Do(gomock.Any()).Return(nil, fmt.Errorf("fail"))
				client.EXPECT().Do(gomock.Any()).Return(nil, fmt.Errorf("fail"))
				client.EXPECT().Do(gomock.Any()).Return(nil, fmt.Errorf("fail"))
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.expect(mockHTTPClient)
			a := &apiV1{
				url:    tt.fields.url,
				client: tt.fields.client,
			}
			got, err := a.sendWithRetries(tt.args.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("sendWithRetries() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("sendWithRetries() got = %v, want %v", got, tt.want)
			}
		})
	}
}