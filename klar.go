package main

import (
	"fmt"
	"github.com/Portshift/klar/docker"
	secrets "github.com/Portshift/klar/kubernetes"
	"github.com/Portshift/klar/utils"
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
	optionClairOutput        = "CLAIR_OUTPUT"
	optionClairAddress       = "CLAIR_ADDR"
	optionKlarTrace          = "KLAR_TRACE"
	optionClairThreshold     = "CLAIR_THRESHOLD"
	optionClairTimeout       = "CLAIR_TIMEOUT"
	optionDockerTimeout      = "DOCKER_TIMEOUT"
	optionJSONOutput         = "JSON_OUTPUT" // deprecate?
	optionFormatOutput       = "FORMAT_OUTPUT"
	optionDockerUser         = "DOCKER_USER"
	optionDockerPassword     = "DOCKER_PASSWORD"
	optionDockerToken        = "DOCKER_TOKEN"
	optionDockerInsecure     = "DOCKER_INSECURE"
	optionDockerPlatformOS   = "DOCKER_PLATFORM_OS"
	optionDockerPlatformArch = "DOCKER_PLATFORM_ARCH"
	optionRegistryInsecure   = "REGISTRY_INSECURE"
	optionWhiteListFile      = "WHITELIST_FILE"
	optionIgnoreUnfixed      = "IGNORE_UNFIXED"
)

var priorities = []string{"Unknown", "Negligible", "Low", "Medium", "High", "Critical", "Defcon1"}

func parseOutputPriority() (string, error) {
	clairOutput := priorities[0]
	outputEnv := os.Getenv(optionClairOutput)
	if outputEnv != "" {
		output := strings.Title(strings.ToLower(outputEnv))
		correct := false
		for _, sev := range priorities {
			if sev == output {
				clairOutput = sev
				correct = true
				break
			}
		}

		if !correct {
			return "", fmt.Errorf("Clair output level %s is not supported, only support %v\n", outputEnv, priorities)
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

type config struct {
	ClairAddr           string
	ClairOutput         string
	Threshold           int
	JSONOutput          bool
	FormatStyle         string
	ClairTimeout        time.Duration
	DockerConfig        docker.Config
	WhiteListFile       string
	IgnoreUnfixed       bool
	ForwardingTargetURL string
}

func newConfig(args []string, url string) (*config, error) {
	clairAddr := os.Getenv(optionClairAddress)
	if clairAddr == "" {
		return nil, fmt.Errorf("Clair address must be provided\n")
	}

	if os.Getenv(optionKlarTrace) != "" {
		utils.Trace = true
	}

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

	username, password, err := secrets.GetSecretDockerCredentialsFromK8(os.Getenv(optionDockerUser), os.Getenv(optionDockerPassword))
	if err != nil {
		return nil, err
	}

	return &config{
		ForwardingTargetURL: url,
		ClairAddr:           clairAddr,
		ClairOutput:         clairOutput,
		Threshold:           parseIntOption(optionClairThreshold),
		JSONOutput:          false,
		FormatStyle:         "standard",
		IgnoreUnfixed:       parseBoolOption(optionIgnoreUnfixed),
		ClairTimeout:        time.Duration(clairTimeout) * time.Minute,
		WhiteListFile:       os.Getenv(optionWhiteListFile),
		DockerConfig: docker.Config{
			ImageName:        args[1],
			User:             username,
			Password:         password,
			Token:            os.Getenv(optionDockerToken),
			InsecureTLS:      parseBoolOption(optionDockerInsecure),
			InsecureRegistry: parseBoolOption(optionRegistryInsecure),
			Timeout:          time.Duration(dockerTimeout) * time.Minute,
			PlatformOS:       os.Getenv(optionDockerPlatformOS),
			PlatformArch:     os.Getenv(optionDockerPlatformArch),
		},
	}, nil
}
