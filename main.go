package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/optiopay/klar/clair"
	"github.com/optiopay/klar/docker"
	"github.com/portshift/klar/forwarding"
	"io/ioutil"
	"net/http"
	"os"
)

var store = make(map[string][]*clair.Vulnerability)


func forwardVulnerabilities(url string, vulnerabilities []*clair.Vulnerability, containerName string, imageName string, podName string, namespaceName string) error {
	var scanData []*forwarding.ContextualVulnerability

	// we remove lots of unused data
	for _, v := range vulnerabilities {
		v.Metadata = nil   //TODO
		v.Description = "" //TODO

		contextualVulnerability := &forwarding.ContextualVulnerability{
			Vulnerability: v,
			Pod:           podName,
			Container:     containerName,
			Image:         imageName,
			Namespace:     namespaceName,
		}
		scanData = append(scanData, contextualVulnerability)
	}
	jsonBody, err := json.Marshal(scanData)
	if err != nil {
		_ = fmt.Errorf("failed to forward vulnerabilities: %v", err)
		return err
	}
	fullUrl := "http://" + url + ":8080/add/"
	fmt.Println("URL:>", fullUrl)
	req, err := http.NewRequest("POST", fullUrl, bytes.NewBuffer(jsonBody))
	if err != nil {
		_ = fmt.Errorf("failed to forward vulnerabilities: %v", err)
		return err
	}
	req.Close = true
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		_ = fmt.Errorf("failed to forward vulnerabilities: %v", err)
		return err
	}
	defer resp.Body.Close()

	fmt.Println("response Status:", resp.Status)
	fmt.Println("response Headers:", resp.Header)
	respBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("response Body:", string(respBody))

	return nil
}

func groupBySeverity(vs []*clair.Vulnerability) {
	for _, v := range vs {
		sevRow := vulsBy(v.Severity, store)
		store[v.Severity] = append(sevRow, v)
	}
}

func vulsBy(sev string, store map[string][]*clair.Vulnerability) []*clair.Vulnerability {
	items, found := store[sev]
	if !found {
		items = make([]*clair.Vulnerability, 0)
		store[sev] = items
	}
	return items
}

// created by Rafael Seidel @ Portshift
func main() {
	fail := func(format string, a ...interface{}) {
		_, _ = fmt.Fprintf(os.Stderr, fmt.Sprintf("%s\n", format), a...)
		os.Exit(2)
	}
	fmt.Printf("ARGS = : %+v", os.Args)
	if len(os.Args) < 5 {
		fail("Image name, container name, pod name and namespace name must be provided (url is optional)")
	}

	imageName := os.Args[1]
	containerName := os.Args[2]
	podName := os.Args[3]
	namespaceName := os.Args[4]
	url := os.Args[5]

	conf, err := newConfig(os.Args, url)
	if err != nil {
		fail("Invalid options: %s", err)
	}

	image, err := docker.NewImage(&conf.DockerConfig)
	if err != nil {
		fail("Can't parse name: %s", err)
	}

	err = image.Pull()
	if err != nil {
		fail("Can't pull image: %s", err)
	}

	if len(image.FsLayers) == 0 {
		fail("Can't pull fsLayers")
	} else {
		fmt.Printf("Analysing %d layers\n", len(image.FsLayers))
	}

	var vulnerabilities []*clair.Vulnerability
	for _, ver := range []int{1, 3} {
		c := clair.NewClair(conf.ClairAddr, ver, conf.ClairTimeout)
		vulnerabilities, err = c.Analyse(image)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Failed to analyze using API v%d: %s\n", ver, err)
		} else {
			if !conf.JSONOutput {
				fmt.Printf("Got results from Clair API v%d\n", ver)
			}
			break
		}
	}
	if err != nil {
		fail("Failed to analyze, exiting...")
	}

	vsNumber := 0

	groupBySeverity(vulnerabilities)

	fmt.Printf("Found %d vulnerabilities\n", len(vulnerabilities))

	vsNumber = standardFormat(conf, vulnerabilities)

	if conf.ForwardingTargetURL != "" {
		err := forwardVulnerabilities(conf.ForwardingTargetURL, vulnerabilities, containerName, imageName, podName, namespaceName)
		if err != nil {
			os.Exit(2)
		}
	}

	if vsNumber > conf.Threshold {
		os.Exit(1)
	}
}
