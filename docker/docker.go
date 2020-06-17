package docker

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/containers/image/v5/docker/reference"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Portshift/klar/utils"
)

const (
	stateInitial = iota
	stateName
	statePort
	stateTag
)

// Image represents Docker image
type Image struct {
	Registry      string
	Name          string
	Tag           string
	FsLayers      []FsLayer
	Token         string
	user          string
	password      string
	client        http.Client
	digest        string
	schemaVersion int
	os            string
	arch          string
}

func (i *Image) LayerName(index int) string {
	s := fmt.Sprintf("%s%s", trimDigest(i.digest),
		trimDigest(i.FsLayers[index].BlobSum))
	return s
}

func (i *Image) AnalyzedLayerName() string {
	index := len(i.FsLayers) - 1
	if i.schemaVersion == 1 {
		index = 0
	}
	return i.LayerName(index)
}

func trimDigest(d string) string {
	return strings.Replace(d, "sha256:", "", 1)
}

// FsLayer represents a layer in docker image
type FsLayer struct {
	BlobSum string
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
		user:     conf.User,
		password: conf.Password,
		Token:    "",
		client:   client,
		os:       "linux",
		arch:     "amd64",
	}

	ref, err := reference.ParseNormalizedNamed(conf.ImageName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image name. name=%v: %v", conf.ImageName, conf.ImageName)
	}

	// strip tag if image has digest and tag
	ref = imageNameWithDigestOrTag(ref)
	// add default tag "latest"
	ref = reference.TagNameOnly(ref)

	image.Registry = reference.Domain(ref)
	// reference.ParseNormalizedNamed setting `defaultDomain`, we need `dockerHub` domain
	if image.Registry == defaultDomain {
		image.Registry = dockerHub
	}
	image.Name = reference.Path(ref)
	if canonical, isDigested := ref.(reference.Canonical); isDigested {
		image.Tag = canonical.Digest().String()
	} else if tagged, isTagged := ref.(reference.NamedTagged); isTagged {
		image.Tag = tagged.Tag()
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

// imageNameWithDigestOrTag strips the tag from ambiguous image references that have a digest as well (e.g. `image:tag@sha256:123...`).
// Based on https://github.com/cri-o/cri-o/pull/3060
func imageNameWithDigestOrTag(named reference.Named) reference.Named {
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
			return err
		}
		// try again
		resp, err = i.pullReq()
		if err != nil {
			return err
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
	return parseImageResponse(resp, i)
}

func parseImageResponse(resp *http.Response, image *Image) error {
	switch contentType := resp.Header.Get("Content-Type"); contentType {
	case "application/vnd.docker.distribution.manifest.v2+json":
		var imageV2 imageV2
		if err := json.NewDecoder(resp.Body).Decode(&imageV2); err != nil {
			fmt.Fprintln(os.Stderr, "Image V2 decode error")
			return err
		}
		image.FsLayers = make([]FsLayer, len(imageV2.Layers))
		for i := range imageV2.Layers {
			image.FsLayers[i].BlobSum = imageV2.Layers[i].Digest
		}
		image.digest = imageV2.Config.Digest
		image.schemaVersion = imageV2.SchemaVersion
	case "application/vnd.docker.distribution.manifest.v1+prettyjws":
		var imageV1 imageV1
		if err := json.NewDecoder(resp.Body).Decode(&imageV1); err != nil {
			fmt.Fprintln(os.Stderr, "ImageV1 decode error")
			return err
		}
		image.FsLayers = make([]FsLayer, len(imageV1.FsLayers))
		// in schemaVersion 1 layers are in reverse order, so we save them in the same order as v2
		// base layer is the first
		for i := range imageV1.FsLayers {
			image.FsLayers[len(imageV1.FsLayers)-1-i].BlobSum = imageV1.FsLayers[i].BlobSum
		}
		image.schemaVersion = imageV1.SchemaVersion
	default:
		return fmt.Errorf("Docker Registry responded with unsupported Content-Type: %s", contentType)
	}
	return nil
}

func parseManifestResponse(resp *http.Response, image *Image) error {
	var manifestlist manifestList
	if err := json.NewDecoder(resp.Body).Decode(&manifestlist); err != nil {
		fmt.Fprintln(os.Stderr, "ManifestList decode error")
		return err
	}
	for _, m := range manifestlist.Manifests {
		if m.Platform.OS == image.os && m.Platform.Architecture == image.arch {
			image.Tag = m.Digest
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

func (i *Image) pullReq() (*http.Response, error) {
	url := fmt.Sprintf("%s/%s/manifests/%s", i.Registry, i.Name, i.Tag)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Can't create a request")
		return nil, err
	}
	if i.Token == "" && i.user != "" {
		req.SetBasicAuth(i.user, i.password)
		i.Token = req.Header.Get("Authorization")
	} else {
		req.Header.Set("Authorization", i.Token)
	}

	// Prefer manifest schema v2
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.v1+prettyjws, application/vnd.docker.distribution.manifest.list.v2+json")
	utils.DumpRequest(req)
	resp, err := i.client.Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Get error")
		return nil, err
	}
	utils.DumpResponse(resp)
	return resp, nil
}
