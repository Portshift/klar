package main

import (
	grype_models "github.com/anchore/grype/grype/presenter/models"

	"github.com/Portshift/klar/config"
	"github.com/Portshift/klar/run"
	"github.com/Portshift/klar/types"

	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/Portshift/klar/forwarding"
	vulutils "github.com/Portshift/klar/utils/vulnerability"
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

	vulnerabilities, commands, err := run.ExecuteRemoteGrypeScan(imageName, conf)
	if err != nil {
		errMsg := fmt.Errorf("failed to execute scan: %w", err)
		log.Error(errMsg)
		result.ScanErr = types.ConvertError(errMsg)
		exit(2, conf, result)
	}

	result.Vulnerabilities = filterVulnerabilities(conf.SeverityThreshold, vulnerabilities)
	result.LayerCommands = commands
	result.Success = true

	log.Infof("Found %d vulnerabilities", len(vulnerabilities.Matches))

	if err := forwarding.SendScanResults(conf.ResultServicePath, result); err != nil {
		log.Errorf("Failed to send scan results: %v", err)
	}
}

func initLogs() {
	if os.Getenv(config.OptionKlarTrace) == "true" {
		log.SetLevel(log.DebugLevel)
	}
}

func filterVulnerabilities(severityThresholdStr string, vulnerabilities *grype_models.Document) *grype_models.Document {
	var filtered []grype_models.Match

	severityThreshold := vulutils.GetSeverityFromString(severityThresholdStr)
	for _, vulnerability := range vulnerabilities.Matches {
		if vulutils.GetSeverityFromString(vulnerability.Vulnerability.Severity) < severityThreshold {
			log.Debugf("Vulnerability severity below threshold. vulnerability=%+v, threshold=%+v", vulnerability,
				severityThresholdStr)
			continue
		}
		filtered = append(filtered, vulnerability)
	}

	vulnerabilities.Matches = filtered

	return vulnerabilities
}
