package main

// created by Rafael Seidel @ Portshift
import (
	"errors"
	"github.com/Portshift-Admin/klar/clair"
	"github.com/Portshift-Admin/klar/docker"
	"github.com/Portshift-Admin/klar/forwarding"
	log "github.com/sirupsen/logrus"
	"os"
)

func sendResultsIfNeeded(url string, imageName string) {
	err := forwarding.SendResultsIfNeeded(url, imageName)
	if err != nil {
		log.Errorf("failed to SendResultsIfNeeded: %v", err)
	}
}

func exit(code int, url string, imageName string) {
	sendResultsIfNeeded(url, imageName)
	os.Exit(code)
}

func getArgs() (string, string, error) {
	if len(os.Args) < 2 {
		return "", "", errors.New("image name  must be provided (forwarding url is optional)")
	}
	imageName := os.Args[1]

	url := ""
	if len(os.Args) >= 3 {
		url = os.Args[2]
	}
	return imageName, url, nil
}

func executeScan(err error, conf *config) (error, []*clair.Vulnerability) {
	image, err := docker.NewImage(&conf.DockerConfig)
	if err != nil {
		log.Errorf("Can't parse name: %v", err)
		return err, nil
	}

	err = image.Pull()
	if err != nil {
		log.Errorf("Can't pull image: %v", err)
		return err, nil
	}

	if len(image.FsLayers) == 0 {
		log.Errorf("Can't pull fsLayers")
		return err, nil
	} else {
		log.Infof("Analysing %d layers\n", len(image.FsLayers))
	}

	var vulnerabilities []*clair.Vulnerability
	for _, ver := range []int{1, 3} {
		c := clair.NewClair(conf.ClairAddr, ver, conf.ClairTimeout)
		vulnerabilities, err = c.Analyse(image)
		if err != nil {
			log.Errorf("Failed to analyze using API v%d: %s\n", ver, err)
		} else {
			if !conf.JSONOutput {
				log.Infof("Got results from Clair API v%d\n", ver)
			}
			break
		}
	}
	return err, vulnerabilities
}

func main() {
	imageName, url, err := getArgs()
	if err != nil {
		log.Errorf("invalid args: %v", err)
		exit(2, url, imageName)
	}

	conf, err := newConfig(os.Args, url)
	if err != nil {
		log.Errorf("Invalid options: %v", err)
		exit(2, url, imageName)
	}
	defer sendResultsIfNeeded(url, imageName)

	err, vulnerabilities := executeScan(err, conf)
	if err != nil {
		log.Errorf("Failed to analyze, exiting...")
		exit(2, url, imageName)
	}

	log.Infof("Found %d vulnerabilities\n", len(vulnerabilities))

	vsNumber := 0
	vsNumber = printVulnerabilities(conf, vulnerabilities)

	if conf.ForwardingTargetURL != "" {
		if len(vulnerabilities) == 0 {
			log.Infof("There were no vulnerabilities! nothing to forward")
		}
		err := forwarding.ForwardVulnerabilities(conf.ForwardingTargetURL, imageName, vulnerabilities, true)
		if err != nil {
			log.Errorf("failed to forward vulnerabilities: %v", err)
			exit(2, url, imageName)
		}
	}

	if conf.Threshold != 0 && vsNumber > conf.Threshold {
		exit(1, url, imageName)
	}
}
