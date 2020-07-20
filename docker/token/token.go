package token

import (
	"context"
	"github.com/Portshift/klar/docker/token/ecr"
	"github.com/Portshift/klar/docker/token/gcr"
	"github.com/Portshift/klar/docker/token/secret"
	"github.com/containers/image/v5/docker/reference"
	log "github.com/sirupsen/logrus"
)

type CredExtractor struct {
	extractors []Extractor
}

type Extractor interface {
	// Prints the name of the extractor
	Name() string
	// Returns true if extractor is supported for extracting credentials for the given image
	IsSupported(named reference.Named) bool
	// Returns the proper credentials for the given image
	GetCredentials(ctx context.Context, named reference.Named) (username, password string, err error)
}

func CreateCredExtractor() *CredExtractor{
	return &CredExtractor{
		extractors: []Extractor{
			// Note: ImagePullSecret must be first
			&secret.ImagePullSecret{},
			&gcr.GCR{},
			&ecr.ECR{},
		},
	}
}

func (c *CredExtractor) GetCredentials(ctx context.Context, named reference.Named) (username, password string, err error) {
	// Found the matched extractor and get credential
	for _, extractor := range c.extractors {
		if !extractor.IsSupported(named) {
			continue
		}

		username, password, err = extractor.GetCredentials(ctx, named)
		if err != nil {
			log.Debugf("failed to get credentials. image=%v: %v", named.Name(), err)
			continue
		}

		log.Debugf("Credentials found. image name=%v, extractor=%v", named.Name(), extractor.Name())
		return username, password, nil
	}

	log.Debugf("Credentials not found. image name=%v.", named.Name())
	return "", "", nil
}