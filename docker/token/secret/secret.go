package secret

import (
	"context"
	"errors"
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

	var generalKeyRing = credentialprovider.NewDockerKeyring()

	generalKeyRing, err = credprovsecrets.MakeDockerKeyring(secrets, generalKeyRing)
	if err != nil {
		return "", "", err
	}

	credentials, _ := generalKeyRing.Lookup(named.Name())
	if len(credentials) != 1 {
		return "", "", errors.New("failed to get secret docker credentials")
	}

	return credentials[0].Username, credentials[0].Password, nil
}
