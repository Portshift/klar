package forwarding

import (
	"bytes"
	"encoding/json"
	"github.com/Portshift-Admin/klar/clair"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
)

var forwarded = false

type ImageVulnerabilities struct {
	Vulnerabilities []*clair.Vulnerability `json:"vulnerability"`
	Image           string                 `json:"image,omitempty"`
	Success         bool                   `json:"success,omitempty"`
}

func SendResultsIfNeeded(url string, imageName string) error {
	if !forwarded {
		log.Infof("Sending empty results")
		err := ForwardVulnerabilities(url, imageName, []*clair.Vulnerability{}, false)
		if err != nil {
			return err
		}
		log.Infof("Sent empty results!")
	}

	return nil
}

func ForwardVulnerabilities(url string, imageName string, vulnerabilities []*clair.Vulnerability, success bool) error {
	scanData := &ImageVulnerabilities{
		Vulnerabilities: vulnerabilities,
		Image:           imageName,
		Success:         success,
	}
	jsonBody, err := json.Marshal(scanData)
	if err != nil {
		return err
	}
	fullUrl := "http://" + url + ":8080/add/"
	log.Infof("URL:> %s", fullUrl)
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
		if resp != nil {
			log.Errorf("response Status:", resp.Status)
		}
		return err
	}
	defer resp.Body.Close()

	log.Infof("response Status: %s", resp.Status)
	log.Debugf("response Headers: %s", resp.Header)
	respBody, _ := ioutil.ReadAll(resp.Body)
	log.Debugf("response Body %s:", string(respBody))
	forwarded = true
	return nil
}
