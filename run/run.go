package run

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Portshift/klar/clair"
	"github.com/Portshift/klar/config"
	"github.com/Portshift/klar/docker"
	grype_models "github.com/anchore/grype/grype/presenter/models"
	anchore_image "github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/formats"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	log "github.com/sirupsen/logrus"
	grype_client "wwwin-github.cisco.com/eti/grype-server/api/client/client"
	grype_client_operations "wwwin-github.cisco.com/eti/grype-server/api/client/client/operations"
	"wwwin-github.cisco.com/eti/grype-server/api/client/models"
)

func ExecuteScanGrype(imageName string, conf *config.Config) (*grype_models.Document, []*docker.FsLayerCommand, error) {
	src, cleanup, err := source.New(imageName, &anchore_image.RegistryOptions{
		InsecureSkipTLSVerify: conf.DockerConfig.InsecureTLS,
		InsecureUseHTTP:       conf.DockerConfig.InsecureRegistry,
		Credentials: []anchore_image.RegistryCredentials{
			{
				Authority: "", // What is this?
				Username:  conf.DockerConfig.User,
				Password:  conf.DockerConfig.Password,
				Token:     conf.DockerConfig.Token,
			},
		},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create syft source: %v", err)
	}
	defer cleanup()


	catalog, d, err := syft.CatalogPackages(src, source.SquashedScope)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to catalog packages: %v", err)
	}

	sbomResult := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			PackageCatalog: catalog,
			Distro:         d,
		},
		Source: src.Metadata,
	}

	f := formats.ByOption(format.JSONOption)
	if f == nil {
		return nil, nil, fmt.Errorf("unknown format: %v", format.JSONOption)
	}
	presenter := f.Presenter(sbomResult)
	if presenter == nil {
		return nil, nil, fmt.Errorf("failed to create presenter")
	}
	sbomBuf := new(bytes.Buffer)
	err = presenter.Present(sbomBuf)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to present sbom: %v", err)
	}
	sbom64 := base64.StdEncoding.EncodeToString([]byte(sbomBuf.String()))

	client := createGrypeClient(conf.GrypeAddr)
	params := grype_client_operations.NewPostScanSBOMParams().WithBody(&models.SBOM{
		Sbom: sbom64,
	})
	ok, err := client.Operations.PostScanSBOM(params)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to send sbom for scan: %v", err)
	}
	doc := grype_models.Document{}
	docB, err := base64.StdEncoding.DecodeString(ok.Payload.Vulnerabilities)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode vulnerabilities: %v", err)
	}
	err = json.Unmarshal(docB, &doc)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshall vulnerabilities document: %v", err)
	}

	commands, err := GetImageCommands(conf)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get image commands : %v", err)
	}

	return &doc, commands, nil
}

func createGrypeClient(serverAddress string) *grype_client.GrypeServer {
	cfg := grype_client.DefaultTransportConfig()
	cfg.WithHost(serverAddress)
	transport := httptransport.New(cfg.Host, cfg.BasePath, cfg.Schemes)
	return grype_client.New(transport, strfmt.Default)
}

func ExecuteScan(conf *config.Config) ([]*clair.Vulnerability, []*docker.FsLayerCommand, error) {
	image, err := docker.NewImage(&conf.DockerConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse name: %v", err)
	}

	err = image.Pull()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to pull image: %w", err)
	}

	if err := image.FetchFsCommands(&conf.DockerConfig); err != nil {
		return nil, nil, fmt.Errorf("failed to fetch layer commands: %v", err)
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

func GetImageCommands(conf *config.Config) ([]*docker.FsLayerCommand, error) {
	image, err := docker.NewImage(&conf.DockerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse name: %v", err)
	}

	err = image.Pull()
	if err != nil {
		return nil, fmt.Errorf("failed to pull image: %w", err)
	}

	if err := image.FetchFsCommands(&conf.DockerConfig); err != nil {
		return nil, fmt.Errorf("failed to fetch layer commands: %v", err)
	}

	if len(image.FsLayers) == 0 {
		return nil, fmt.Errorf("failed to pull pull fsLayers")
	}

	return image.GetFsCommands(), nil
}