package run

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/anchore/grype/grype"
	grype_db "github.com/anchore/grype/grype/db"
	grype_pkg "github.com/anchore/grype/grype/pkg"
	grype_models "github.com/anchore/grype/grype/presenter/models"

	grype_client "github.com/Portshift/grype-server/api/client/client"
	grype_client_operations "github.com/Portshift/grype-server/api/client/client/operations"
	"github.com/Portshift/grype-server/api/client/models"
	"github.com/Portshift/klar/config"
	"github.com/Portshift/klar/docker"
	anchore_image "github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/source"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

func ExecuteRemoteGrypeScan(imageName string, conf *config.Config) (*grype_models.Document, []*docker.FsLayerCommand, error) {
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

	catalog, distro, err := syft.CatalogPackages(src, source.SquashedScope)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to catalog packages: %v", err)
	}
	sbomEncoded, err := syft.Encode(catalog, &src.Metadata, distro, source.SquashedScope, format.JSONOption)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode sbom: %v", err)
	}

	sbom64 := base64.StdEncoding.EncodeToString(sbomEncoded)

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

func ExecuteLocalGrypeScan(imageName string, conf *config.Config) (*grype_models.Document, []*docker.FsLayerCommand, error) {
	dbConfig := grype_db.Config{
		DBRootDir:           "/tmp/",
		ListingURL:          "https://toolbox-data.anchore.io/grype/databases/listing.json",
		ValidateByHashOnGet: false,
	}
	provider, metadataProvider, dbStatus, err := grype.LoadVulnerabilityDB(dbConfig, true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load vulnerability DB: %w", err)
	}
	if dbStatus == nil {
		return nil, nil, fmt.Errorf("unable to determine DB status")
	}

	registryOptions := &anchore_image.RegistryOptions{
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
	}
	packages, context, err := grype_pkg.Provide(imageName, source.SquashedScope, registryOptions)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to analyze packages: %v", err)
	}

	allMatches := grype.FindVulnerabilitiesForPackage(provider, context.Distro, packages...)

	doc, err := grype_models.NewDocument(packages, context, allMatches, nil, metadataProvider, nil, dbStatus)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create document: %v", err)
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
