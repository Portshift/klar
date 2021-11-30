package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/Portshift/klar/docker"
	"github.com/Portshift/klar/utils"
	"github.com/Portshift/klar/utils/vulnerability"
)

const (
	OptionGrypeAddress       = "GRYPE_ADDR"
	OptionGrypeServerTimeout = "GRYPE_SERVER_TIMEOUT"
	OptionKlarTrace          = "KLAR_TRACE"
	OptionSeverityThreshold  = "SEVERITY_THRESHOLD"
	OptionDockerTimeout      = "DOCKER_TIMEOUT"
	OptionDockerUser         = "DOCKER_USER"
	OptionDockerPassword     = "DOCKER_PASSWORD"
	OptionDockerToken        = "DOCKER_TOKEN"
	OptionDockerInsecure     = "DOCKER_INSECURE"
	OptionDockerPlatformOS   = "DOCKER_PLATFORM_OS"
	OptionDockerPlatformArch = "DOCKER_PLATFORM_ARCH"
	OptionRegistryInsecure   = "REGISTRY_INSECURE"
	OptionWhiteListFile      = "WHITELIST_FILE"
	OptionResultServicePath  = "RESULT_SERVICE_PATH"
)

func parseIntOption(key string) int {
	val := 0
	valStr := os.Getenv(key)
	if valStr != "" {
		val, _ = strconv.Atoi(valStr)
	}
	return val
}

func parseBoolOption(key string) bool {
	val := false
	if envVal, err := strconv.ParseBool(os.Getenv(key)); err == nil {
		val = envVal
	}
	return val
}

type Config struct {
	GrypeAddr          string
	GrypeServerTimeout time.Duration
	SeverityThreshold  string
	JSONOutput         bool
	FormatStyle        string
	DockerConfig       docker.Config
	WhiteListFile      string
	IgnoreUnfixed      bool
	ResultServicePath  string
	LocalScanDbPath    string
}

func NewConfig(imageName string) (*Config, error) {
	grypeAddr := os.Getenv(OptionGrypeAddress)
	if grypeAddr == "" {
		return nil, fmt.Errorf("grype address must be provided")
	}

	utils.Trace = os.Getenv(OptionKlarTrace) == "true"

	severityThreshold := os.Getenv(OptionSeverityThreshold)
	if severityThreshold == "" {
		severityThreshold = vulnerability.UnknownVulnerability
	} else {
		if err := vulnerability.ValidateSeverity(severityThreshold); err != nil {
			return nil, err
		}
	}

	grypeServerTimeout := parseIntOption(OptionGrypeServerTimeout)
	if grypeServerTimeout == 0 {
		grypeServerTimeout = 1
	}

	dockerTimeout := parseIntOption(OptionDockerTimeout)
	if dockerTimeout == 0 {
		dockerTimeout = 1
	}

	return &Config{
		ResultServicePath:  os.Getenv(OptionResultServicePath),
		GrypeAddr:          grypeAddr,
		GrypeServerTimeout: time.Duration(grypeServerTimeout) * time.Minute,
		SeverityThreshold:  severityThreshold,
		WhiteListFile:      os.Getenv(OptionWhiteListFile),
		DockerConfig: docker.Config{
			ImageName:        imageName,
			User:             os.Getenv(OptionDockerUser),
			Password:         os.Getenv(OptionDockerPassword),
			Token:            os.Getenv(OptionDockerToken),
			InsecureTLS:      parseBoolOption(OptionDockerInsecure),
			InsecureRegistry: parseBoolOption(OptionRegistryInsecure),
			Timeout:          time.Duration(dockerTimeout) * time.Minute,
			PlatformOS:       os.Getenv(OptionDockerPlatformOS),
			PlatformArch:     os.Getenv(OptionDockerPlatformArch),
		},
	}, nil
}
