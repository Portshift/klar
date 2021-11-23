package config

import (
	"fmt"
	"github.com/Portshift/klar/docker"
	"github.com/Portshift/klar/utils"
	"k8s.io/kubernetes/pkg/util/slice"
	"os"
	"strconv"
	"time"
)

//Used to represent the structure of the whitelist YAML file
type vulnerabilitiesWhitelistYAML struct {
	General []string
	Images  map[string][]string
}

const (
	OptionGrypeAddress       = "GRYPE_ADDR"
	OptionKlarTrace          = "KLAR_TRACE"
	OptionSeverityThreshold  = "SEVERITY_THRESHOLD"
	OptionScanTimeout        = "SCAN_TIMEOUT"
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

var severities = []string{"Unknown", "Negligible", "Low", "Medium", "High", "Critical", "Defcon1"}

func validateThresholdSeverity(severity string) (error) {
	if !slice.ContainsString(severities, severity, nil) {
		return fmt.Errorf("invalid saverity threshold: %v", severity)
	}

	return nil
}

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
	GrypeAddr         string
	SeverityThreshold string
	JSONOutput        bool
	FormatStyle       string
	ScanTimeout       time.Duration
	DockerConfig      docker.Config
	WhiteListFile     string
	IgnoreUnfixed     bool
	ResultServicePath string
}

func NewConfig(imageName string) (*Config, error) {
	grypeAddr := os.Getenv(OptionGrypeAddress)
	if grypeAddr == "" {
		return nil, fmt.Errorf("grype address must be provided")
	}

	utils.Trace = os.Getenv(OptionKlarTrace) == "true"

	severityThreshold := os.Getenv(OptionSeverityThreshold)
	err := validateThresholdSeverity(severityThreshold)
	if err != nil {
		return nil, err
	}

	scanTimeout := parseIntOption(OptionScanTimeout)
	if scanTimeout == 0 {
		scanTimeout = 1
	}

	dockerTimeout := parseIntOption(OptionDockerTimeout)
	if dockerTimeout == 0 {
		dockerTimeout = 1
	}

	return &Config{
		ResultServicePath: os.Getenv(OptionResultServicePath),
		GrypeAddr:         grypeAddr,
		SeverityThreshold: severityThreshold,
		ScanTimeout:       time.Duration(scanTimeout) * time.Minute,
		WhiteListFile:     os.Getenv(OptionWhiteListFile),
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
