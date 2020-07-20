package ecr

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/containers/image/v5/docker/reference"
)

const ecrURL = "amazonaws.com"

type ECR struct {}

func (e *ECR) Name() string {
	return "ecr"
}

func (e *ECR) IsSupported(named reference.Named) bool {
	return strings.HasSuffix(reference.Domain(named), ecrURL)
}

func (e *ECR) GetCredentials(ctx context.Context, _ reference.Named) (username, password string, err error) {
	input := &ecr.GetAuthorizationTokenInput{}

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	client := ecr.New(sess)

	result, err := client.GetAuthorizationTokenWithContext(ctx, input)
	if err != nil {
		return "", "", fmt.Errorf("failed to get authorization token: %w", err)
	}

	for _, data := range result.AuthorizationData {
		b, err := base64.StdEncoding.DecodeString(*data.AuthorizationToken)
		if err != nil {
			return "", "", fmt.Errorf("base64 decode failed: %w", err)
		}
		// e.g. AWS:eyJwYXlsb2...
		split := strings.SplitN(string(b), ":", 2)
		if len(split) == 2 {
			return split[0], split[1], nil
		}
	}

	return "", "", nil
}
