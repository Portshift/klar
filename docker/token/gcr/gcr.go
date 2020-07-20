package gcr

import (
	"context"
	"strings"

	"github.com/GoogleCloudPlatform/docker-credential-gcr/config"
	"github.com/GoogleCloudPlatform/docker-credential-gcr/credhelper"
	"github.com/GoogleCloudPlatform/docker-credential-gcr/store"
	"github.com/containers/image/v5/docker/reference"
)

const gcrURL = "gcr.io"

type GCR struct {}

func (g *GCR) Name() string {
	return "gcr"
}

func (g *GCR) IsSupported(named reference.Named) bool {
	return strings.HasSuffix(reference.Domain(named), gcrURL)
}

func (g *GCR) GetCredentials(_ context.Context, named reference.Named) (username, password string, err error) {
	credStore, err := store.DefaultGCRCredStore()
	if err != nil {
		return "", "", err
	}

	userCfg, err := config.LoadUserConfig()
	if err != nil {
		return "", "", err
	}

	return credhelper.NewGCRCredentialHelper(credStore, userCfg).Get(reference.Domain(named))
}
