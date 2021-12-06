package run

import (
	"encoding/json"
	"fmt"
	"github.com/anchore/grype/grype"
	grype_db "github.com/anchore/grype/grype/db"
	grype_pkg "github.com/anchore/grype/grype/pkg"
	grype_models "github.com/anchore/grype/grype/presenter/models"
	log "github.com/sirupsen/logrus"
	"time"

	anchore_image "github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/source"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	grype_client "github.com/Portshift/grype-server/api/client/client"
	grype_client_operations "github.com/Portshift/grype-server/api/client/client/operations"
	"github.com/Portshift/grype-server/api/client/models"
	"github.com/Portshift/klar/config"
	"github.com/Portshift/klar/docker"
)

// ExecuteRemoteGrypeScan Executes the vulnerability scan remotely by invoking the Grype Server. It will fetch the image,
//// analyze the SBOM and invoke the Grype Server scanner.
func ExecuteRemoteGrypeScan(imageName string, conf *config.Config) (*grype_models.Document, []*docker.FsLayerCommand, error) {
	updateConfigCredentialsIfNeeded(imageName, conf)
	commands, err := docker.FetchFsCommands(&conf.DockerConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get image commands : %v", err)
	}
	src, cleanup, err := source.New(setImageSource(imageName, conf), createRegistryOptions(conf))
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

	doc, err := scanSbomWithGrypeServer(conf.GrypeAddr, conf.GrypeServerTimeout, sbomEncoded)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to scan sbom using Grype Server: %v", err)
	}

	return doc, commands, nil
}

func setImageSource(imageName string, conf *config.Config) string {
	if conf.DockerConfig.Local {
		return "docker:"+imageName
	} else {
		return "registry:"+imageName
	}
}

func scanSbomWithGrypeServer(serverAddress string, timeout time.Duration, sbom []byte) (*grype_models.Document, error) {
	client := createGrypeClient(serverAddress)
	params := grype_client_operations.NewPostScanSBOMParams().WithBody(&models.SBOM{
		Sbom: sbom,
	}).WithTimeout(timeout)
	ok, err := client.Operations.PostScanSBOM(params)
	if err != nil {
		return nil, fmt.Errorf("failed to send sbom for scan: %v", err)
	}
	doc := grype_models.Document{}

	err = json.Unmarshal(ok.Payload.Vulnerabilities, &doc)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshall vulnerabilities document: %v", err)
	}
	return &doc, nil
}

func validateDBLoad(loadErr error, status *grype_db.Status) error {
	if loadErr != nil {
		return fmt.Errorf("failed to load vulnerability db: %w", loadErr)
	}
	if status == nil {
		return fmt.Errorf("unable to determine DB status")
	}
	if status.Err != nil {
		return fmt.Errorf("db could not be loaded: %w", status.Err)
	}
	return nil
}

// ExecuteStandaloneGrypeScan Executes the vulnerability scan locally without invoking the Grype Server. It will fetch the image,
// analyze the SBOM, fetch the vulnerability DB and perform the scan.
func ExecuteStandaloneGrypeScan(imageName string, conf *config.Config) (*grype_models.Document, []*docker.FsLayerCommand, error) {
	dbConfig := grype_db.Config{
		DBRootDir:           conf.StandaloneScanDbPath,
		ListingURL:          "https://toolbox-data.anchore.io/grype/databases/listing.json",
		ValidateByHashOnGet: false,
	}
	provider, metadataProvider, dbStatus, dbErr := grype.LoadVulnerabilityDB(dbConfig, true)

	if err := validateDBLoad(dbErr, dbStatus); err != nil {
		return nil, nil, fmt.Errorf("failed to load DB: %v", err)
	}

	updateConfigCredentialsIfNeeded(imageName, conf)

	commands, err := docker.FetchFsCommands(&conf.DockerConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get image commands : %v", err)
	}

	registryOptions := createRegistryOptions(conf)

	packages, context, err := grype_pkg.Provide(setImageSource(imageName, conf), source.SquashedScope, registryOptions)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to analyze packages: %v", err)
	}

	allMatches := grype.FindVulnerabilitiesForPackage(provider, context.Distro, packages...)

	doc, err := grype_models.NewDocument(packages, context, allMatches, nil, metadataProvider, nil, dbStatus)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create document: %v", err)
	}

	return &doc, commands, nil
}
func updateConfigCredentialsIfNeeded(imageName string, conf *config.Config) {
	if conf.DockerConfig.User == "" || conf.DockerConfig.Password == "" {
		username, password, err := docker.ExtractCredentials(imageName)
		if err != nil {
			log.Warnf("Failed to extract credentials for image %v: %v", imageName, err)
			return
		}
		conf.DockerConfig.User = username
		conf.DockerConfig.Password = password
	}
}

func createRegistryOptions(conf *config.Config) *anchore_image.RegistryOptions {
	registryOptions := &anchore_image.RegistryOptions{
		InsecureSkipTLSVerify: conf.DockerConfig.InsecureTLS,
		InsecureUseHTTP:       conf.DockerConfig.InsecureRegistry,
		Credentials: []anchore_image.RegistryCredentials{
			{
				Username: conf.DockerConfig.User,
				Password: conf.DockerConfig.Password,
				Token:    conf.DockerConfig.Token,
			},
		},
	}
	return registryOptions
}

func createGrypeClient(serverAddress string) *grype_client.GrypeServer {
	cfg := grype_client.DefaultTransportConfig()
	cfg.WithHost(serverAddress)
	transport := httptransport.New(cfg.Host, cfg.BasePath, cfg.Schemes)
	return grype_client.New(transport, strfmt.Default)
}
