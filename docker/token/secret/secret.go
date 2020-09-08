package secret

import (
	"context"
	"fmt"
	"os"

	"github.com/containers/image/v5/docker/reference"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/kubernetes/pkg/credentialprovider"
	credprovsecrets "k8s.io/kubernetes/pkg/credentialprovider/secrets"
)

const ImagePullSecretEnvVar = "K8S_IMAGE_PULL_SECRET"

type ImagePullSecret struct {
	body string
}

func (s *ImagePullSecret) Name() string {
	return "ImagePullSecret"
}

func (s *ImagePullSecret) IsSupported(_ reference.Named) bool {
	s.body = os.Getenv(ImagePullSecretEnvVar)
	return s.body != ""
}

func (s *ImagePullSecret) GetCredentials(_ context.Context, named reference.Named) (username, password string, err error) {
	secretDataMap := make(map[string][]byte)

	secretDataMap[corev1.DockerConfigJsonKey] = []byte(s.body)
	secrets := []corev1.Secret{{
		Data:       secretDataMap,
		Type:       corev1.SecretTypeDockerConfigJson,
	}}

	dockerKeyring, err := credprovsecrets.MakeDockerKeyring(secrets, credentialprovider.NewDockerKeyring())
	if err != nil {
		return "", "", fmt.Errorf("failed to create docker keyring: %v", err)
	}

	credentials, credentialsExist := dockerKeyring.Lookup(named.Name())
	if !credentialsExist {
		return "", "", fmt.Errorf("failed to get image credentials. image=%v", named.Name())
	}

	// using the first credentials found as they are the most specific match for this image
	return credentials[0].Username, credentials[0].Password, nil
}
