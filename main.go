package main

// created by Rafael Seidel @ Portshift
import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/Portshift-Admin/klar/clair"
	"github.com/Portshift-Admin/klar/docker"
	"github.com/Portshift-Admin/klar/forwarding"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"os"
)

var forwarded = false

func forwardVulnerabilities(url string, imageName string, vulnerabilities []*clair.Vulnerability) error {
	var scanData []*forwarding.ContextualVulnerability
	for _, v := range vulnerabilities {
		contextualVulnerability := &forwarding.ContextualVulnerability{
			Vulnerability: v,
			Image:         imageName,
		}
		scanData = append(scanData, contextualVulnerability)
	}
	jsonBody, err := json.Marshal(scanData)
	if err != nil {
		log.Errorf("failed to forward vulnerabilities: %v", err)
		return err
	}
	fullUrl := "http://" + url + ":8080/add/"
	log.Printf("URL:> %s", fullUrl)
	buffer := bytes.NewBuffer(jsonBody)

	req, err := http.NewRequest("POST", fullUrl, buffer)
	if err != nil {
		log.Errorf("failed to forward vulnerabilities: %v", err)
		return err
	}
	req.Close = true
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		log.Errorf("failed to forward vulnerabilities: %v", err)
		log.Printf("RESPONSE STATUS:> %+v", resp.Status)
		return err
	}
	defer resp.Body.Close()

	log.Printf("response Status:", resp.Status)
	log.Printf("response Headers:", resp.Header)
	respBody, _ := ioutil.ReadAll(resp.Body)
	log.Printf("response Body:", string(respBody))
	forwarded = true
	return nil
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
		os.Exit(2)
	}

	err = image.Pull()
	if err != nil {
		log.Errorf("Can't pull image: %v", err)
		os.Exit(2)
	}

	if len(image.FsLayers) == 0 {
		log.Errorf("Can't pull fsLayers")
		os.Exit(2)
	} else {
		log.Printf("Analysing %d layers\n", len(image.FsLayers))
	}

	var vulnerabilities []*clair.Vulnerability
	for _, ver := range []int{1, 3} {
		c := clair.NewClair(conf.ClairAddr, ver, conf.ClairTimeout)
		vulnerabilities, err = c.Analyse(image)
		if err != nil {
			log.Errorf("Failed to analyze using API v%d: %s\n", ver, err)
		} else {
			if !conf.JSONOutput {
				log.Printf("Got results from Clair API v%d\n", ver)
			}
			break
		}
	}
	return err, vulnerabilities
}

// created by Rafael Seidel @ Portshift
func main() {

	imageName, url, err := getArgs()
	if err != nil {
		log.Errorf("invalid args: %v", err)
		os.Exit(2)
	}

	defer SendResultsIfNeeded(url, imageName)

	conf, err := newConfig(os.Args, url)
	if err != nil {
		log.Errorf("Invalid options: %v", err)
		os.Exit(2)
	}

	err, vulnerabilities := executeScan(err, conf)
	if err != nil {
		log.Errorf("Failed to analyze, exiting...")
		os.Exit(2)
	}

	vsNumber := 0

	log.Printf("RAFI: Found %d vulnerabilities\n", len(vulnerabilities))

	vsNumber = printVulnerabilities(conf, vulnerabilities)

	if conf.ForwardingTargetURL != "" {
		if len(vulnerabilities) == 0 {
			log.Printf("There were no vulnerabilities! nothing to forward")
		} else {
			err := forwardVulnerabilities(conf.ForwardingTargetURL, imageName, vulnerabilities)
			if err != nil {
				log.Errorf("failed to forward vulnerabilities: %v", err)
				os.Exit(2)
			}
		}
	}

	if vsNumber > conf.Threshold {
		os.Exit(1)
	}
}

func SendResultsIfNeeded(url string, imageName string) {
	if !forwarded {
		err := forwardVulnerabilities(url, imageName, []*clair.Vulnerability{})
		if err != nil {
			log.Errorf("failed to SendResultsIfNeeded: %v", err)
			os.Exit(2)
		}
	}
}
