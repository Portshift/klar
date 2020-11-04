package client

import (
	"fmt"
	"github.com/Portshift/klar/clair"
	"github.com/Portshift/klar/docker"
	"github.com/Portshift/klar/utils"
	log "github.com/sirupsen/logrus"
	"os"
	"strconv"
	"strings"
	"time"
)

//Used to represent the structure of the whitelist YAML file
type vulnerabilitiesWhitelistYAML struct {
	General []string
	Images  map[string][]string
}

const (
	OptionKlarTrace        = "KLAR_TRACE"
	optionClairOutput      = "CLAIR_OUTPUT"
	optionClairAddress     = "CLAIR_ADDR"
	optionClairThreshold   = "CLAIR_THRESHOLD"
	optionClairTimeout     = "CLAIR_TIMEOUT"
	optionDockerTimeout    = "DOCKER_TIMEOUT"
	optionJSONOutput       = "JSON_OUTPUT" // deprecate?
	optionFormatOutput     = "FORMAT_OUTPUT"
	optionDockerUser       = "DOCKER_USER"
	optionDockerPassword   = "DOCKER_PASSWORD"
	optionDockerToken      = "DOCKER_TOKEN"
	optionDockerInsecure   = "DOCKER_INSECURE"
	optionDockerPlatformOS = "DOCKER_PLATFORM_OS"
	optionDockerPlatformArch = "DOCKER_PLATFORM_ARCH"
	optionRegistryInsecure   = "REGISTRY_INSECURE"
	optionWhiteListFile      = "WHITELIST_FILE"
	optionIgnoreUnfixed      = "IGNORE_UNFIXED"
	optionResultServicePath  = "RESULT_SERVICE_PATH"
)

var Priorities = []string{"Unknown", "Negligible", "Low", "Medium", "High", "Critical", "Defcon1"}

func parseOutputPriority() (string, error) {
	clairOutput := Priorities[0]
	outputEnv := os.Getenv(optionClairOutput)
	if outputEnv != "" {
		output := strings.Title(strings.ToLower(outputEnv))
		correct := false
		for _, sev := range Priorities {
			if sev == output {
				clairOutput = sev
				correct = true
				break
			}
		}

		if !correct {
			return "", fmt.Errorf("Clair output level %s is not supported, only support %v\n", outputEnv, Priorities)
		}
	}
	return clairOutput, nil
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
	ClairAddr         string
	ClairOutput       string
	Threshold         int
	JSONOutput        bool
	FormatStyle       string
	ClairTimeout      time.Duration
	DockerConfig      docker.Config
	WhiteListFile     string
	IgnoreUnfixed     bool
	ResultServicePath string
}

func ExecuteScan(conf *Config) ([]*clair.Vulnerability, error) {
	image, err := docker.NewImage(&conf.DockerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse name: %v", err)
	}

	err = image.Pull()
	if err != nil {
		return nil, fmt.Errorf("failed to pull image: %v", err)
	}

	if len(image.FsLayers) == 0 {
		return nil, fmt.Errorf("failed to pull pull fsLayers")
	}

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

	return vulnerabilities, err
}

func NewConfig(imageName string) (*Config, error) {
	clairAddr := os.Getenv(optionClairAddress)
	if clairAddr == "" {
		return nil, fmt.Errorf("clair address must be provided")
	}

	utils.Trace = os.Getenv(OptionKlarTrace) == "true"

	clairOutput, err := parseOutputPriority()
	if err != nil {
		return nil, err
	}

	clairTimeout := parseIntOption(optionClairTimeout)
	if clairTimeout == 0 {
		clairTimeout = 1
	}

	dockerTimeout := parseIntOption(optionDockerTimeout)
	if dockerTimeout == 0 {
		dockerTimeout = 1
	}

	return &Config{
		ResultServicePath: os.Getenv(optionResultServicePath),
		ClairAddr:         clairAddr,
		ClairOutput:       clairOutput,
		Threshold:         parseIntOption(optionClairThreshold),
		JSONOutput:        false,
		FormatStyle:       "standard",
		IgnoreUnfixed:     parseBoolOption(optionIgnoreUnfixed),
		ClairTimeout:      time.Duration(clairTimeout) * time.Minute,
		WhiteListFile:     os.Getenv(optionWhiteListFile),
		DockerConfig: docker.Config{
			ImageName:        imageName,
			User:             os.Getenv(optionDockerUser),
			Password:         os.Getenv(optionDockerPassword),
			Token:            os.Getenv(optionDockerToken),
			InsecureTLS:      parseBoolOption(optionDockerInsecure),
			InsecureRegistry: parseBoolOption(optionRegistryInsecure),
			Timeout:          time.Duration(dockerTimeout) * time.Minute,
			PlatformOS:       os.Getenv(optionDockerPlatformOS),
			PlatformArch:     os.Getenv(optionDockerPlatformArch),
		},
	}, nil
}
