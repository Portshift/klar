package main

import (
	//	"bytes"
	"encoding/json"
	//"github.com/aquasecurity/fanal/image/daemon"
	"github.com/containers/image/v5/pkg/blobinfocache/none"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/opencontainers/go-digest"
	"golang.org/x/xerrors"
	"time"

	//"encoding/json"
	"fmt"
	"github.com/Portshift/klar/clair"
	"github.com/Portshift/klar/docker"
	"github.com/Portshift/klar/forwarding"
	vulutils "github.com/Portshift/klar/utils/vulnerability"
	docker_v5 "github.com/containers/image/v5/docker"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/manifest"
	image_types "github.com/containers/image/v5/types"
	log "github.com/sirupsen/logrus"
	"context"
	//fanal_image "github.com/aquasecurity/fanal/image"
	fanal_types "github.com/aquasecurity/fanal/types"
	//"github.com/wagoodman/dive/dive"
	"os"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/google/go-containerregistry/pkg/authn"
	fanal_token "github.com/aquasecurity/fanal/image/token"

	"net/http"
	"crypto/tls"
)

func exit(code int, conf *config, scanResults *forwarding.ImageVulnerabilities) {
	if err := forwarding.SendScanResults(conf.ResultServicePath, scanResults); err != nil {
		log.Errorf("Failed to send scan results: %v", err)
	}
	os.Exit(code)
}

func getImageName() (string, error) {
	if len(os.Args) < 2 {
		return "", fmt.Errorf("image name must be provided")
	}

	return os.Args[1], nil
}

//func showCommandsDive(imageName string) {
//	sourceType, imageStr := dive.DeriveImageSource(imageName)
//
//	if sourceType == dive.SourceUnknown {
//		sourceType = dive.SourceDockerEngine
//		imageStr = imageName
//	}
//	imageResolver, err := dive.GetImageResolver(sourceType)
//	if err != nil {
//		log.Fatalf("Failed to get image resolver: %v", err)
//	}
//	img, err := imageResolver.Fetch(imageStr)
//	if err != nil {
//		log.Fatalf("Failed to fetch image: %v", err)
//	}
//	log.Errorf("Fatched")
//	analysis, err := img.Analyze()
//	if err != nil {
//		log.Fatalf("Failed to analyze image: %v", err)
//	}
//	log.Errorf("Analyzed")
//	//layersB, err := json.Marshal(analysis.Layers)
//	for _, layer := range analysis.Layers {
//		log.Errorf("layer: id=%v, command=%v, digest=%v, index=%v, names=%v, size=%v", layer.Id, layer.Command, layer.Digest, layer.Index, layer.Names, layer.Size)
//	}
//
//}

func getLayers(imageName string) []string {
	ctx := context.Background()

	opts := fanal_types.DockerOption{
		Timeout:  90*time.Second,
		SkipPing: true,
	}
	img, cleanup, err := newDockerImage(ctx, imageName, opts)
	if err != nil {
		log.Fatalf("Failed to get docker image: %v", err)
	}
	defer cleanup()

	conf, err := img.ConfigFile()
	if err != nil {
		log.Fatalf("Failed to get config file: %v", err)
	}
	confB, err := json.Marshal(conf)
	if err != nil {
		log.Fatalf("Failed to marshal config: %v", err)
	}
	log.Errorf("confB: %s", confB)
	var layerCommands []string
	for i, layerHistory := range conf.History {
		if layerHistory.EmptyLayer {
			log.Errorf("Skipping empty layer (%v): %s", i, layerHistory)
		}
		layerCommands = append(layerCommands, layerHistory.CreatedBy)
	}
	manifest, err := img.Manifest()
	manifestB, err := json.Marshal(manifest)
	if err != nil {
		log.Fatalf("Failed to marshal manifest: %v", err)
	}

	mediaType, err := img.MediaType()
	if err != nil {
		log.Fatalf("Failed to get media type: %v", err)
	}
	log.Errorf("MediaType=%v, imgmanifestB: %s", mediaType, manifestB)

	return layerCommands
}

func newDockerImage(ctx context.Context, imageName string, option fanal_types.DockerOption) (v1.Image, func(), error) {
	var result error

	var nameOpts []name.Option
	if option.NonSSL {
		nameOpts = append(nameOpts, name.Insecure)
	}
	ref, err := name.ParseReference(imageName, nameOpts...)
	if err != nil {
		return nil, func() {}, xerrors.Errorf("failed to parse the image name: %w", err)
	}

	//// Try accessing Docker Daemon
	//img, cleanup, err := daemon.Image(ref)
	//if err == nil {
	//	// Return v1.Image if the image is found in Docker Engine
	//	return img, cleanup, nil
	//}
	//result = multierror.Append(result, err)

	// Try accessing Docker Registry
	var remoteOpts []remote.Option
	if option.InsecureSkipTLSVerify {
		t := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		remoteOpts = append(remoteOpts, remote.WithTransport(t))
	}

	domain := ref.Context().RegistryStr()
	auth := fanal_token.GetToken(ctx, domain, option)

	if auth.Username != "" && auth.Password != "" {
		remoteOpts = append(remoteOpts, remote.WithAuth(&auth))
	} else if option.RegistryToken != "" {
		bearer := authn.Bearer{Token: option.RegistryToken}
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

func showCommandsDocker(imageName string) {
	namedImageRef, err := reference.ParseNormalizedNamed(imageName)
	namedImageRef = reference.TagNameOnly(namedImageRef)
	if err != nil {
		log.Fatalf("Failed ParseNormalizedNamed: %+v", err)
	}
	log.Errorf("Image: %v", namedImageRef.String())
	sysCtx := &image_types.SystemContext{}
	imageReference, err := docker_v5.NewReference(namedImageRef)
	if err != nil {
		log.Fatalf("Failed to get image reference: %+v", err)
	}
	ctx := context.Background()

	imageSrc, err := imageReference.NewImageSource(ctx, sysCtx)
	if err != nil {
		log.Fatalf("Failed to get image source reference: %v", err)
	}

	defer func() {
		if err := imageSrc.Close(); err != nil {
			log.Warn("failed to close image reference source.")
		}
	}()
	rawManifest, _, err := imageSrc.GetManifest(ctx, nil)
	if err != nil {
		log.Fatalf("failed to get image manifest: %v", err)
	}
	dig, err := manifest.Digest(rawManifest)
	if err != nil {
		log.Fatalf("failed to get dig from manifest: %v", err)
	}
	rawManifest, _, err = imageSrc.GetManifest(ctx, &dig)
	if err != nil {
		log.Fatalf("failed to get image manifest: %v", err)
	}
	log.Errorf("rawManifest: %s", rawManifest)
	schema2, err := manifest.Schema2FromManifest(rawManifest)
	if err != nil {
		log.Fatalf("failed to get schema 2 from manifest: %v", err)
	}
	schema2B, _ := json.Marshal(schema2)
	log.Errorf("schema2: %s", schema2B)

	blobDigest := digest.Digest("sha256:6d82ad84c781486ab0ef444c41d893182680e73d44b43f7e01d0deddbd710772")
	blobManifest, _, err := imageSrc.GetManifest(ctx, &blobDigest)
	if err != nil {
		log.Fatalf("failed to get blob manifest: %v", err)
	}
	log.Errorf("blobManifest: %s", blobManifest)

	//imageSrc.GetManifest(ctx, imageReference)
	blob, _, err := imageSrc.GetBlob(ctx, image_types.BlobInfo{
		Digest:               "sha256:6d82ad84c781486ab0ef444c41d893182680e73d44b43f7e01d0deddbd710772",//"sha256:0bda4312074bccc8c7efa87e896555caebe5fff902557c07307855b2dba9106c",//schema2.ConfigDescriptor.Digest,
	} , none.NoCache)
	if err != nil {
		log.Fatalf("Failed to get blob: %v", err)
	}

	buf := make([]byte,0,5000)
	n, err := blob.Read(buf)
	if err != nil {
		log.Fatalf("Failed to read blob: %v", err)
	}
	log.Errorf("N: %v", n)
	log.Errorf("blob: %s", buf)
	defer blob.Close()
	//log.Errorf("rawManifest:=", rawManifest.Read())

	// ----------------
	//ctx := context.Background()
	//dockerOption := deckodertypes.DockerOption{
	//	Timeout:  90*time.Second,
	//}
	//ext := extractor.NewDockerExtractor(dockerOption)
	//fileMap, err := ext.Extract(ctx, imageName, nil)
	//if err != nil {
	//	log.Fatalf("Failed to extract file map: %v", err)
	//}
	//config, ok := fileMap["/config"]
	//if !ok {
	//	log.Fatalf(("config json file doesn't exist")
	//}
	//log.Errorf("##########config: %s", config.Body)

}
/*
func (d DockerExtractor) Extract(ctx context.Context, imageName string, filterFunc types.FilterFunc) (extractor.FileMap, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d.Option.Timeout)
	defer cancel()

	image, err := registry.ParseImage(imageName)
	if err != nil {
		return nil, err
	}
	r, err := d.createRegistryClient(ctx, image.Domain)
	if err != nil {
		return nil, fmt.Errorf("failed to create registry: %w", err)
	}

	// Get the v2 manifest.
	manifest, err := r.Manifest(ctx, image.Path, image.Reference())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch manifest: %w", err)
	}
	m, ok := manifest.(*schema2.DeserializedManifest)
	if !ok {
		return nil, errors.New("failed to match scheme: manifest v2")
	}

	ch := make(chan layer)
	errCh := make(chan error)
	layerIDs := []string{}
	for _, ref := range m.Manifest.Layers {
		layerIDs = append(layerIDs, string(ref.Digest))
		go func(d digest.Digest) {
			// Use cache
			rc := cache.Get(string(d))
			if rc == nil {
				// Download the layer.
				rc, err = r.DownloadLayer(ctx, image.Path, d)
				if err != nil {
					errCh <- fmt.Errorf("failed to download the layer(%s): %w", d, err)
					return
				}
				rc, err = cache.Set(string(d), rc)
				if err != nil {
					log.Print(err)
				}
			}
			gzipReader, err := gzip.NewReader(rc)
			if err != nil {
				errCh <- fmt.Errorf("invalid gzip: %w", err)
				return
			}
			ch <- layer{ID: d, Content: gzipReader}
		}(ref.Digest)
	}

	filesInLayers := make(map[string]extractor.FileMap)
	opqInLayers := make(map[string]opqDirs)
	for i := 0; i < len(m.Manifest.Layers); i++ {
		var l layer
		select {
		case l = <-ch:
		case err := <-errCh:
			return nil, err
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout: %w", ctx.Err())
		}
		files, opqDirs, err := d.ExtractFiles(l.Content, filterFunc)
		if err != nil {
			return nil, err
		}
		layerID := string(l.ID)
		filesInLayers[layerID] = files
		opqInLayers[layerID] = opqDirs
	}

	fileMap, err := applyLayers(layerIDs, filesInLayers, opqInLayers)
	if err != nil {
		return nil, fmt.Errorf("failed to apply layers: %w", err)
	}

	// download config file
	rc, err := r.DownloadLayer(ctx, image.Path, m.Manifest.Config.Digest)
	if err != nil {
		return nil, fmt.Errorf("error in layer download: %w", err)
	}
	config, err := ioutil.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to decode config JSON: %w", err)
	}

	// special file for command analyzer
	fileMap["/config"] = extractor.FileData{Body: config, FileMode: os.ModePerm}

	return fileMap, nil
}
 */
func executeScan(conf *config) ([]*clair.Vulnerability, []*docker.FsLayerCommand, error) {
	image, err := docker.NewImage(&conf.DockerConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse name: %v", err)
	}

	err = image.Pull()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to pull image: %v", err)
	}

	if len(image.FsLayers) == 0 {
		return nil, nil, fmt.Errorf("failed to pull pull fsLayers")
	}

	commands := image.GetFsCommands()

	log.Infof("Analysing %d layers", len(image.FsLayers))

	var vulnerabilities []*clair.Vulnerability

	c := clair.NewClair(conf.ClairAddr, conf.ClairTimeout)
	vulnerabilities, err = c.Analyse(image)
	if err != nil {
		log.Errorf("Failed to analyze using API: %s", err)
	} else {
		if !conf.JSONOutput {
			log.Infof("Got results from Clair API")
		}
	}

	return vulnerabilities, commands, err
}

func main() {
	initLogs()

	result := &forwarding.ImageVulnerabilities{
		Success:  false,
		ScanUUID: os.Getenv("SCAN_UUID"),
	}

	imageName, err := getImageName()
	if err != nil {
		log.Error(err)
		os.Exit(2)
	}

	result.Image = imageName

	conf, err := newConfig(imageName)
	if err != nil {
		log.Errorf("Invalid options: %v", err)
		os.Exit(2)
	}

	vulnerabilities, commands, err := executeScan(conf)
	if err != nil {
		errStr := fmt.Sprintf("Failed to execute scan: %v", err)
		log.Errorf(errStr)
		result.ScanErrMsg = errStr
		exit(2, conf, result)
	}

	result.Vulnerabilities = filterVulnerabilities(conf.ClairOutput, vulnerabilities)
	result.LayerCommands = commands
	result.Success = true

	resultB, err := json.Marshal(result)
	if err != nil {
		log.Errorf("Failed to marshal result: %v", err)
		os.Exit(2)
	}
	log.Infof("resultB: %s", resultB)

	log.Infof("Found %d vulnerabilities", len(vulnerabilities))
	vsNumber := printVulnerabilities(conf, vulnerabilities)

	if conf.Threshold != 0 && vsNumber > conf.Threshold {
		exit(1, conf, result)
	}

	if err := forwarding.SendScanResults(conf.ResultServicePath, result); err != nil {
		log.Errorf("Failed to send scan results: %v", err)
	}
}

func initLogs() {
	if os.Getenv(optionKlarTrace) == "true" {
		log.SetLevel(log.DebugLevel)
	}
}

func filterVulnerabilities(severityThresholdStr string, vulnerabilities []*clair.Vulnerability) []*clair.Vulnerability {
	var ret []*clair.Vulnerability

	severityThreshold := vulutils.GetSeverityFromString(severityThresholdStr)
	for _, vulnerability := range vulnerabilities {
		if vulutils.GetSeverityFromString(vulnerability.Severity) < severityThreshold {
			log.Debugf("Vulnerability severity below threshold. vulnerability=%+v, threshold=%+v", vulnerability,
				severityThresholdStr)
			continue
		}
		ret = append(ret, vulnerability)
	}

	return ret
}