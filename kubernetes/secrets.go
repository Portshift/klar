package secrets

import (
	"errors"
	"github.com/docker/distribution/reference"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/pkg/credentialprovider"
	credprovsecrets "k8s.io/kubernetes/pkg/credentialprovider/secrets"
	"os"
)

const ImagePullSecretEnvVar = "K8S_IMAGE_PULL_SECRET"

func GetSecretDockerCredentialsFromK8(username string, password string) (string, string, error) {
	secretJsonBody := os.Getenv(ImagePullSecretEnvVar)
	if secretJsonBody != "" {
		imageName := os.Args[1]

		secretDataMap := make(map[string][]byte)

		secretDataMap[corev1.DockerConfigJsonKey] = []byte(secretJsonBody)
		secrets := []corev1.Secret{{
			TypeMeta:   v1.TypeMeta{},
			ObjectMeta: v1.ObjectMeta{},
			Data:       secretDataMap,
			StringData: nil,
			Type:       corev1.SecretTypeDockerConfigJson,
		}}

		var generalKeyRing = credentialprovider.NewDockerKeyring()
		generalKeyRing, err := credprovsecrets.MakeDockerKeyring(secrets, generalKeyRing)
		if err != nil {
			return "", "", err
		}
		namedImageRef, err := reference.ParseNormalizedNamed(imageName)
		if err != nil {
			return "", "", err

		}
		credentials, _ := generalKeyRing.Lookup(namedImageRef.Name())
		if len(credentials) != 1 {
			return "", "", errors.New("failed to get secret docker credentials")
		}
		username = credentials[0].Username
		password = credentials[0].Password
	}
	return username, password, nil
}
