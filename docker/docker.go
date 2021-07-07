package docker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Portshift/klar/types"

	"github.com/Portshift/klar/docker/token"
	"github.com/containers/image/v5/docker/reference"
	docker_manifest "github.com/containers/image/v5/manifest"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/daemon"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"

	containerregistry_v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/Portshift/klar/utils"
)

// Image represents Docker image
type Image struct {
	Registry      string
	Name          string
	Reference     string // Tag or digest
	FsLayers      []FsLayer
	FsCommands    []*FsLayerCommand
	Token         string
	user          string
	password      string
	client        http.Client
	Digest        string
	schemaVersion int
	os            string
	arch          string
	imageName     string
}

func (i *Image) LayerName(index int) string {
	s := fmt.Sprintf("%s%s", TrimDigest(i.Digest),
		TrimDigest(i.FsLayers[index].BlobSum))
	return s
}

func (i *Image) AnalyzedLayerName() string {
	index := len(i.FsLayers) - 1
	if i.schemaVersion == 1 {
		index = 0
	}
	return i.LayerName(index)
}

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

const dockerHub = "registry-1.docker.io"

// github.com/containers/image/v5/docker/reference/normalize.go
const defaultDomain = "docker.io"

var tokenRe = regexp.MustCompile(`Bearer realm="(.*?)",service="(.*?)",scope="(.*?)"`)

// NewImage parses image name which could be the ful name registry:port/name:tag
// or in any other shorter forms and creates docker image entity without
// information about layers
func NewImage(conf *Config) (*Image, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: conf.InsecureTLS},
		Proxy:           http.ProxyFromEnvironment,
	}
	client := http.Client{
		Transport: tr,
		Timeout:   conf.Timeout,
	}

	image := &Image{
		user:      conf.User,
		password:  conf.Password,
		Token:     "",
		client:    client,
		os:        "linux",
		arch:      "amd64",
		imageName: conf.ImageName,
	}

	ref, err := getImageRef(conf.ImageName)
	if err != nil {
		return nil, fmt.Errorf("failed to get image ref. image name=%v: %v", conf.ImageName, err)
	}

	image.Registry = reference.Domain(ref)
	// reference.ParseNormalizedNamed setting `defaultDomain`, we need `dockerHub` domain
	if image.Registry == defaultDomain {
		image.Registry = dockerHub
	}
	image.Name = reference.Path(ref)
	if canonical, isDigested := ref.(reference.Canonical); isDigested {
		image.Reference = canonical.Digest().String()
	} else if tagged, isTagged := ref.(reference.NamedTagged); isTagged {
		image.Reference = tagged.Tag()
	}

	if image.user == "" || image.password == "" {
		credExtractor := token.CreateCredExtractor()
		if image.user, image.password, err = credExtractor.GetCredentials(context.Background(), ref); err != nil {
			return nil, fmt.Errorf("failed to get credentials. image name=%v: %v", conf.ImageName, err)
		}
		// update the config with the fetched credentials in case it will be needed again out of the Image scope
		conf.User = image.user
		conf.Password = image.password
	}

	if conf.InsecureRegistry {
		image.Registry = fmt.Sprintf("http://%s/v2", image.Registry)
	} else {
		image.Registry = fmt.Sprintf("https://%s/v2", image.Registry)
	}
	if conf.Token != "" {
		image.Token = "Basic " + conf.Token
	}
	if conf.PlatformOS != "" {
		image.os = conf.PlatformOS
	}
	if conf.PlatformArch != "" {
		image.arch = conf.PlatformArch
	}

	return image, nil
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

// Pull retrieves information about layers from docker registry.
// It gets docker registry token if needed.
func (i *Image) Pull() error {
	resp, err := i.pullReq()
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		i.Token, err = i.requestToken(resp)
		io.Copy(ioutil.Discard, resp.Body)
		if err != nil {
			dump, dumpErr := httputil.DumpResponse(resp, false)
			if dumpErr != nil {
				return fmt.Errorf("failed to request token. dump error=%+v: %v. %w", dumpErr, err, types.ErrorUnauthorized)
			}
			return fmt.Errorf("failed to request token. response=%s: %v, %w", string(dump), err, types.ErrorUnauthorized)
		}
		// try again
		resp, err = i.pullReq()
		if err != nil {
			return fmt.Errorf("%v. %w", err, types.ErrorUnauthorized)
		}
		defer resp.Body.Close()
	}

	if contentType := resp.Header.Get("Content-Type"); contentType == "application/vnd.docker.distribution.manifest.list.v2+json" {
		err = parseManifestResponse(resp, i)
		if err != nil {
			return err
		}
		// pull actual manifest instead of manifestlist
		resp, err = i.pullReq()
		if err != nil {
			return err
		}
		defer resp.Body.Close()
	}

	if err := parseImageResponse(resp, i); err != nil {
		return fmt.Errorf("failed to parse image response. request url=%s: %w", i.getPullReqUrl(), err)
	}

	return nil
}

func (i *Image) GetFsCommands() []*FsLayerCommand {
	return i.FsCommands
}

func (i *Image) FetchFsCommands(config *Config) error {
	if i.FsCommands != nil {
		log.Infof("Layer commands are already present")
		return nil
	}

	fsCommands, err := FetchFsCommands(config)
	if err != nil {
		return fmt.Errorf("failed to fetch layer commands: %v", err)
	}
	i.FsCommands = fsCommands

	return nil
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
		layerDigest, err := layer.Digest()
		if err != nil {
			return nil, fmt.Errorf("failed to get layer digest: %v", err)
		}
		layerCommands = append(layerCommands, &FsLayerCommand{
			Command: commands[i],
			Layer:   layerDigest.Hex,
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

func parseImageResponse(resp *http.Response, image *Image) error {
	switch contentType := resp.Header.Get("Content-Type"); contentType {
	case "application/vnd.docker.distribution.manifest.v2+json", "application/vnd.oci.image.manifest.v1+json":
		var imageV2 imageV2
		if err := json.NewDecoder(resp.Body).Decode(&imageV2); err != nil {
			fmt.Fprintln(os.Stderr, "Image V2 decode error")
			return err
		}
		image.FsLayers = make([]FsLayer, len(imageV2.Layers))
		for i := range imageV2.Layers {
			image.FsLayers[i].BlobSum = imageV2.Layers[i].Digest
		}
		image.Digest = imageV2.Config.Digest
		image.schemaVersion = imageV2.SchemaVersion
	case "application/vnd.docker.distribution.manifest.v1+prettyjws":
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %v", err)
		}
		schema1, err := docker_manifest.Schema1FromManifest(body)
		if err != nil {
			return fmt.Errorf("failed to convert schema1 from manifest: %v", err)
		}
		for i, compatibility := range schema1.ExtractedV1Compatibility {
			log.Debugf("layer %v: cmd: %v", i, compatibility.ContainerConfig.Cmd)
		}
		if len(schema1.FSLayers) != len(schema1.ExtractedV1Compatibility) {
			return fmt.Errorf("number of layers(%v) doesn't match the number of commands(%v)", len(schema1.FSLayers), len(schema1.ExtractedV1Compatibility))
		}
		extractV1LayersWithCommands(image, schema1)
		image.schemaVersion = schema1.SchemaVersion
	default:
		err := getErrorFromStatusCode(resp.StatusCode)
		dump, dumpErr := httputil.DumpResponse(resp, false)
		if dumpErr != nil {
			return fmt.Errorf("docker Registry responded with unsupported Content-Type (%v). dump error=%+v. %w", contentType, dumpErr, err)
		}

		return fmt.Errorf("docker Registry responded with unsupported Content-Type: response=%s. %w", string(dump), err)
	}
	return nil
}

func getErrorFromStatusCode(code int) error {
	switch code {
	case http.StatusUnauthorized:
		return types.ErrorUnauthorized
	case http.StatusForbidden:
		return types.ErrorForbidden
	default:
		return types.ErrorUnknown
	}
}

// Strips Dockerfile generation info from layer commands. e.g: "/bin/sh -c #(nop) CMD [/bin/bash]" -> "CMD [/bin/bash]"
func stripDockerMetaFromCommand(command string) string {
	ret := strings.TrimSpace(strings.TrimPrefix(command, "/bin/sh -c #(nop)"))
	ret = strings.TrimSpace(strings.TrimPrefix(ret, "/bin/sh -c"))
	return ret
}

func extractV1LayersWithCommands(image *Image, schema1 *docker_manifest.Schema1) {
	image.FsLayers = make([]FsLayer, len(schema1.FSLayers))
	image.FsCommands = make([]*FsLayerCommand, len(schema1.FSLayers))
	// in schemaVersion 1 layers and commands are in reverse order, so we save them in the same order as v2
	// base layer is the first
	for i := range schema1.FSLayers {
		image.FsLayers[len(schema1.FSLayers)-1-i].BlobSum = schema1.FSLayers[i].BlobSum.String()
		image.FsCommands[len(schema1.FSLayers)-1-i] = &FsLayerCommand{
			Command: stripDockerMetaFromCommand(strings.Join(schema1.ExtractedV1Compatibility[i].ContainerConfig.Cmd, " ")),
			Layer:   schema1.FSLayers[i].BlobSum.Hex(),
		}
	}
}

func parseManifestResponse(resp *http.Response, image *Image) error {
	var manifestlist manifestList
	if err := json.NewDecoder(resp.Body).Decode(&manifestlist); err != nil {
		fmt.Fprintln(os.Stderr, "ManifestList decode error")
		return err
	}
	for _, m := range manifestlist.Manifests {
		if m.Platform.OS == image.os && m.Platform.Architecture == image.arch {
			image.Reference = m.Digest
			return nil
		}
	}
	return fmt.Errorf("Did not find the specified platform (os: %s, arch: %s) in the manifest list.", image.os, image.arch)
}

func (i *Image) requestToken(resp *http.Response) (string, error) {
	authHeader := resp.Header.Get("Www-Authenticate")
	if authHeader == "" {
		return "", fmt.Errorf("Empty Www-Authenticate")
	}
	parts := tokenRe.FindStringSubmatch(authHeader)
	if parts == nil {
		return "", fmt.Errorf("Can't parse Www-Authenticate: %s", authHeader)
	}
	realm, service, scope := parts[1], parts[2], parts[3]
	var url string
	if i.user != "" {
		url = fmt.Sprintf("%s?service=%s&scope=%s&account=%s", realm, service, scope, i.user)
	} else {
		url = fmt.Sprintf("%s?service=%s&scope=%s", realm, service, scope)
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Can't create a request")
		return "", err
	}
	if i.user != "" {
		req.SetBasicAuth(i.user, i.password)
	}
	tResp, err := i.client.Do(req)
	if err != nil {
		if tResp != nil {
			io.Copy(ioutil.Discard, tResp.Body)
		}
		return "", err
	}

	defer tResp.Body.Close()
	if tResp.StatusCode != http.StatusOK {
		io.Copy(ioutil.Discard, tResp.Body)
		return "", fmt.Errorf("Token request returned %d", tResp.StatusCode)
	}
	var tokenEnv struct {
		Token string
	}

	if err = json.NewDecoder(tResp.Body).Decode(&tokenEnv); err != nil {
		fmt.Fprintln(os.Stderr, "Token response decode error")
		return "", err
	}
	return fmt.Sprintf("Bearer %s", tokenEnv.Token), nil
}

func (i *Image) getPullReqUrl() string {
	return fmt.Sprintf("%s/%s/manifests/%s", i.Registry, i.Name, i.Reference)
}

func (i *Image) pullReq() (*http.Response, error) {
	url := i.getPullReqUrl()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to create a request")
		return nil, fmt.Errorf("failed to create a request. url=%v: %v", url, err)
	}
	if i.Token == "" && i.user != "" {
		req.SetBasicAuth(i.user, i.password)
		i.Token = req.Header.Get("Authorization")
	} else {
		req.Header.Set("Authorization", i.Token)
	}

	// Prefer manifest schema v2
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.v1+prettyjws, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json")
	utils.DumpRequest(req)
	resp, err := i.client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed execute the request")
		return nil, fmt.Errorf("failed execute the request. url=%v: %v", url, err)
	}
	utils.DumpResponse(resp)
	return resp, nil
}
