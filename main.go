package main

import (
	"github.com/Portshift/klar/config"
	"github.com/Portshift/klar/format"
	"github.com/Portshift/klar/run"
	"github.com/Portshift/klar/types"

	"fmt"
	"github.com/Portshift/klar/clair"
	"github.com/Portshift/klar/forwarding"
	vulutils "github.com/Portshift/klar/utils/vulnerability"
	log "github.com/sirupsen/logrus"
	"os"
)

func exit(code int, conf *config.Config, scanResults *forwarding.ImageVulnerabilities) {
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

	conf, err := config.NewConfig(imageName)
	if err != nil {
		log.Errorf("Invalid options: %v", err)
		os.Exit(2)
	}

	vulnerabilities, commands, err := run.ExecuteScan(conf)
	if err != nil {
		errMsg := fmt.Errorf("failed to execute scan: %w", err)
		log.Error(errMsg)
		result.ScanErr = types.ConvertError(errMsg)
		exit(2, conf, result)
	}

	result.Vulnerabilities = filterVulnerabilities(conf.ClairOutput, vulnerabilities)
	result.LayerCommands = commands
	result.Success = true

	log.Infof("Found %d vulnerabilities", len(vulnerabilities))
	vsNumber := format.PrintVulnerabilities(conf, vulnerabilities)

	if conf.Threshold != 0 && vsNumber > conf.Threshold {
		exit(1, conf, result)
	}

	if err := forwarding.SendScanResults(conf.ResultServicePath, result); err != nil {
		log.Errorf("Failed to send scan results: %v", err)
	}
}

func initLogs() {
	if os.Getenv(config.OptionKlarTrace) == "true" {
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
