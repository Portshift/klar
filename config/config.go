package config

import (
	"fmt"
	"github.com/Portshift/klar/docker"
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
	OptionClairOutput        = "CLAIR_OUTPUT"
	OptionClairAddress       = "CLAIR_ADDR"
	OptionKlarTrace          = "KLAR_TRACE"
	OptionClairThreshold     = "CLAIR_THRESHOLD"
	OptionClairTimeout       = "CLAIR_TIMEOUT"
	OptionDockerTimeout      = "DOCKER_TIMEOUT"
	OptionJSONOutput         = "JSON_OUTPUT" // deprecate?
	OptionFormatOutput       = "FORMAT_OUTPUT"
	OptionDockerUser         = "DOCKER_USER"
	OptionDockerPassword     = "DOCKER_PASSWORD"
	OptionDockerToken        = "DOCKER_TOKEN"
	OptionDockerInsecure     = "DOCKER_INSECURE"
	OptionDockerPlatformOS   = "DOCKER_PLATFORM_OS"
	OptionDockerPlatformArch = "DOCKER_PLATFORM_ARCH"
	OptionRegistryInsecure   = "REGISTRY_INSECURE"
	OptionWhiteListFile      = "WHITELIST_FILE"
	OptionIgnoreUnfixed      = "IGNORE_UNFIXED"
	OptionResultServicePath  = "RESULT_SERVICE_PATH"
)

var Priorities = []string{"Unknown", "Negligible", "Low", "Medium", "High", "Critical", "Defcon1"}

func parseOutputPriority() (string, error) {
	clairOutput := Priorities[0]
	outputEnv := os.Getenv(OptionClairOutput)
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

func NewConfig(imageName string) (*Config, error) {
	clairAddr := os.Getenv(OptionClairAddress)
	if clairAddr == "" {
		return nil, fmt.Errorf("clair address must be provided")
	}

	utils.Trace = os.Getenv(OptionKlarTrace) == "true"

	clairOutput, err := parseOutputPriority()
	if err != nil {
		return nil, err
	}

	clairTimeout := parseIntOption(OptionClairTimeout)
	if clairTimeout == 0 {
		clairTimeout = 1
	}

	dockerTimeout := parseIntOption(OptionDockerTimeout)
	if dockerTimeout == 0 {
		dockerTimeout = 1
	}

	return &Config{
		ResultServicePath: os.Getenv(OptionResultServicePath),
		ClairAddr:         clairAddr,
		ClairOutput:       clairOutput,
		Threshold:         parseIntOption(OptionClairThreshold),
		JSONOutput:        false,
		FormatStyle:       "standard",
		IgnoreUnfixed:     parseBoolOption(OptionIgnoreUnfixed),
		ClairTimeout:      time.Duration(clairTimeout) * time.Minute,
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
