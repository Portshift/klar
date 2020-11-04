package main

import (
	"fmt"
	"github.com/Portshift/klar/clair"
	"github.com/Portshift/klar/docker"
	"github.com/Portshift/klar/forwarding"
	vulutils "github.com/Portshift/klar/utils/vulnerability"
	log "github.com/sirupsen/logrus"
	"os"
)

func exit(code int, conf *Config, scanResults *forwarding.ImageVulnerabilities) {
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

	conf, err := newConfig(imageName)
	if err != nil {
		log.Errorf("Invalid options: %v", err)
		os.Exit(2)
	}

	vulnerabilities, err := ExecuteScan(conf)
	if err != nil {
		errStr := fmt.Sprintf("Failed to execute scan: %v", err)
		log.Errorf(errStr)
		result.ScanErrMsg = errStr
		exit(2, conf, result)
	}

	result.Vulnerabilities = filterVulnerabilities(conf.ClairOutput, vulnerabilities)
	result.Success = true

	log.Infof("Found %d vulnerabilities", len(vulnerabilities))
	vsNumber := printVulnerabilities(conf, vulnerabilities)

	if conf.Threshold != 0 && vsNumber > conf.Threshold {
		exit(1, conf, result)
	}

	if err := forwarding.SendScanResults(conf.ResultServicePath, result); err != nil {
		log.Errorf("Failed to send scan results: %v", err)
	}
}

func initLogs() {
	if os.Getenv(optionKlarTrace) == "true" {
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