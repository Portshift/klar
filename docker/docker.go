package docker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/containers/image/v5/docker/reference"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"

	"github.com/Portshift/klar/docker/token"

	containerregistry_v1 "github.com/google/go-containerregistry/pkg/v1"
)

func TrimDigest(d string) string {
	return strings.Replace(d, "sha256:", "", 1)
}

// FsLayer represents a layer in docker image
type FsLayer struct {
	BlobSum string
}

// FsLayerCommand represents a history command of a layer in a docker image
type FsLayerCommand struct {
	Command string
	Layer   string
}

// ImageV1 represents a Manifest V 2, Schema 1 Docker Image
type imageV1 struct {
	SchemaVersion int
	FsLayers      []fsLayer
}

// FsLayer represents a layer in a Manifest V 2, Schema 1 Docker Image
type fsLayer struct {
	BlobSum string
}

type config struct {
	MediaType string
	Digest    string
}

// imageV2 represents Manifest V 2, Schema 2 Docker Image
type imageV2 struct {
	SchemaVersion int
	Config        config
	Layers        []layer
}

// Layer represents a layer in a Manifest V 2, Schema 2 Docker Image
type layer struct {
	Digest string
}

// ManifestList represents a ManifestList V 2
type manifestList struct {
	SchemaVersion int
	MediaType     string
	Manifests     []manifest
}

// Manifest represents a manifest item in a ManifestList V 2
type manifest struct {
	MediaType string
	Size      int
	Digest    string
	Platform  platform
}

type platform struct {
	Architecture string
	OS           string
	Variant      string
}

type Config struct {
	ImageName        string
	User             string
	Password         string
	Token            string
	InsecureTLS      bool
	InsecureRegistry bool
	Timeout          time.Duration
	PlatformOS       string
	PlatformArch     string
	Local            bool
}

var tokenRe = regexp.MustCompile(`Bearer realm="(.*?)",service="(.*?)",scope="(.*?)"`)

func ExtractCredentials(imageName string) (username string, password string, err error){
	ref, err := getImageRef(imageName)
	if err != nil {
		return "", "", fmt.Errorf("failed to get image ref. image name=%v: %v", imageName, err)
	}

	credExtractor := token.CreateCredExtractor()
	if username, password, err = credExtractor.GetCredentials(context.Background(), ref); err != nil {
		return "", "", fmt.Errorf("failed to get credentials. image name=%v: %v", imageName, err)
	}

	return username, password, nil
}

func getImageRef(imageName string) (reference.Named, error) {
	ref, err := reference.ParseNormalizedNamed(imageName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image name. name=%v: %v", imageName, err)
	}

	// strip tag if image has digest and tag
	ref = ImageNameWithDigestOrTag(ref)
	// add default tag "latest"
	ref = reference.TagNameOnly(ref)

	return ref, nil
}

// ImageNameWithDigestOrTag strips the tag from ambiguous image references that have a digest as well (e.g. `image:tag@sha256:123...`).
// Based on https://github.com/cri-o/cri-o/pull/3060
func ImageNameWithDigestOrTag(named reference.Named) reference.Named {
	_, isTagged := named.(reference.NamedTagged)
	canonical, isDigested := named.(reference.Canonical)
	if isTagged && isDigested {
		canonical, err := reference.WithDigest(reference.TrimNamed(named), canonical.Digest())
		if err != nil {
			log.Errorf("Failed to create canonical reference - returning the given name. name=%v, %v", named.Name(), err)
			return named
		}

		return canonical
	}

	return named
}

// FetchFsCommands retrieves information about image layers commands.
func FetchFsCommands(config *Config) ([]*FsLayerCommand, error) {
	var img containerregistry_v1.Image
	if config.Local {
		// Fetch from docker daemon
		localImage, err := newLocalDockerImage(config)
		if err != nil {
			return nil, fmt.Errorf("failed to get local image: %v", err)
		}
		img = localImage
	} else {
		// Fetch from registry
		remoteImage, cleanup, err := newRemoteDockerImage(config)
		if err != nil {
			return nil, fmt.Errorf("failed to get remote image: %v", err)
		}
		img = remoteImage
		defer cleanup()
	}

	conf, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("failed to get config file: %v", err)
	}
	confB, err := json.Marshal(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %v", err)
	}
	log.Debugf("Image config: %s", confB)

	var commands []string
	for i, layerHistory := range conf.History {
		if layerHistory.EmptyLayer {
			log.Infof("Skipping empty layer (%v): %+v", i, layerHistory)
			continue
		}
		commands = append(commands, stripDockerMetaFromCommand(layerHistory.CreatedBy))

	}
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("failed to get layers: %v", err)
	}
	if len(layers) != len(commands) {
		return nil, fmt.Errorf("number of fs layers (%v) doesn't match the number of fs history entries (%v)", len(layers), len(commands))
	}

	var layerCommands []*FsLayerCommand
	for i, layer := range layers {
		layerDiffID, err := layer.DiffID() // Grype specifies the Hash of the uncompressed layer in the result vulnerabilities
		if err != nil {
			return nil, fmt.Errorf("failed to get layer diffID: %v", err)
		}
		layerCommands = append(layerCommands, &FsLayerCommand{
			Command: commands[i],
			Layer:   layerDiffID.Hex,
		})
	}

	layerCommandsB, err := json.Marshal(layerCommands)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal layer commands: %v", err)
	}
	log.Debugf("Layers commands: %s", layerCommandsB)

	return layerCommands, nil
}

func newRemoteDockerImage(config *Config) (containerregistry_v1.Image, func(), error) {
	var result error

	var nameOpts []name.Option
	if config.InsecureRegistry {
		nameOpts = append(nameOpts, name.Insecure)
	}
	user := config.User
	password := config.Password
	if user == "" || password == "" {
		ref, err := getImageRef(config.ImageName)
		if err != nil {
			return nil, func() {}, fmt.Errorf("failed to get image ref. image name=%v: %v", config.ImageName, err)
		}

		credExtractor := token.CreateCredExtractor()
		if user, password, err = credExtractor.GetCredentials(context.Background(), ref); err != nil {
			return nil, func() {}, fmt.Errorf("failed to get credentials. image name=%v: %v", config.ImageName, err)
		}

	}
	ref, err := name.ParseReference(config.ImageName, nameOpts...)
	if err != nil {
		return nil, func() {}, xerrors.Errorf("failed to parse the image name: %w", err)
	}

	// Try accessing Docker Registry
	var remoteOpts []remote.Option
	if config.InsecureTLS {
		t := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		remoteOpts = append(remoteOpts, remote.WithTransport(t))
	}

	if user != "" && password != "" {
		remoteOpts = append(remoteOpts, remote.WithAuth(&authn.Basic{
			Username: user,
			Password: password,
		}))
	} else if config.Token != "" {
		bearer := authn.Bearer{Token: config.Token}
		remoteOpts = append(remoteOpts, remote.WithAuth(&bearer))
	} else {
		remoteOpts = append(remoteOpts, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	}

	img, err := remote.Image(ref, remoteOpts...)
	if err == nil {
		// Return v1.Image if the image is found in Docker Registry
		return img, func() {}, nil
	}
	result = multierror.Append(result, err)

	return nil, func() {}, result
}

func newLocalDockerImage(config *Config) (containerregistry_v1.Image, error) {
	var nameOpts []name.Option
	if config.InsecureRegistry {
		nameOpts = append(nameOpts, name.Insecure)
	}
	ref, err := name.ParseReference(config.ImageName, nameOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the image name: %w", err)
	}

	img, err := daemon.Image(ref, daemon.WithUnbufferedOpener())
	if err != nil {
		return nil, fmt.Errorf("failed to get the image from daemon: %w", err)
	}

	return img, nil
}

// Strips Dockerfile generation info from layer commands. e.g: "/bin/sh -c #(nop) CMD [/bin/bash]" -> "CMD [/bin/bash]"
func stripDockerMetaFromCommand(command string) string {
	ret := strings.TrimSpace(strings.TrimPrefix(command, "/bin/sh -c #(nop)"))
	ret = strings.TrimSpace(strings.TrimPrefix(ret, "/bin/sh -c"))
	return ret
}
