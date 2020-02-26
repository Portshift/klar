package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/optiopay/klar/clair"
	"github.com/optiopay/klar/docker"
	"io/ioutil"
	"net/http"
	"os"
)

var store = make(map[string][]*clair.Vulnerability)

type Data struct {
	Vulnerabilities []*clair.Vulnerability 		 	 `json:"vulnerabilities"`
	Container        string                          `json:"total,omitempty"`
	Image   		 string                          `json:"totalCritical,omitempty"`
}

func maintest() {
	fail := func(format string, a ...interface{}) {
		_, _ = fmt.Fprintf(os.Stderr, fmt.Sprintf("%s\n", format), a...)
		os.Exit(2)
	}

	var vulnerabilities []*clair.Vulnerability
	vul1 := &clair.Vulnerability{
		Name:           "CVE-2019-19603",
		NamespaceName:  "NamespaceName",
		Description:    "Description",
		Link:           "Link",
		Severity:       "HIGH",
		Metadata:       nil,
		FixedBy:        "FixedBy",
		FixedIn:        nil,
		FeatureName:    "FeatureName",
		FeatureVersion: "FeatureVersion",
	}
	vul2 := &clair.Vulnerability{
		Name:           "CVE-2019-20218",
		NamespaceName:  "NamespaceName",
		Description:    "Description",
		Link:           "Link",
		Severity:       "MEDIUM",
		Metadata:       nil,
		FixedBy:        "FixedBy",
		FixedIn:        nil,
		FeatureName:    "FeatureName",
		FeatureVersion: "FeatureVersion",
	}

	vulnerabilities = append(vulnerabilities, vul1)
	vulnerabilities = append(vulnerabilities, vul2)

	marshal, err := json.Marshal(vulnerabilities)
	if err != nil {
		fail("Failed to analyze, exiting")
	}

	forwardVulnerabilities("http://localhost:8080/vuls/", marshal)
}

func forwardVulnerabilities(url string, jsonBody []byte) {
	fmt.Println("URL:>", url)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println("response Status:", resp.Status)
	fmt.Println("response Headers:", resp.Header)
	respBody, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("response Body:", string(respBody))
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

//Filter out whitelisted vulnerabilities
func filterWhitelist(whitelist *vulnerabilitiesWhitelist, vs []*clair.Vulnerability, imageName string) []*clair.Vulnerability {
	generalWhitelist := whitelist.General
	imageWhitelist := whitelist.Images

	filteredVs := make([]*clair.Vulnerability, 0, len(vs))

	for _, v := range vs {
		if _, exists := generalWhitelist[v.Name]; !exists {
			if _, exists := imageWhitelist[imageName][v.Name]; !exists {
				//vulnerability is not in the image whitelist, so add it to the list to return
				filteredVs = append(filteredVs, v)
			}
		}
	}

	return filteredVs
}

func main() {
	fail := func(format string, a ...interface{}) {
		_, _ = fmt.Fprintf(os.Stderr, fmt.Sprintf("%s\n", format), a...)
		os.Exit(2)
	}

	if len(os.Args) != 3 {
		fail("Image name and container name must be provided")
	}

	imageName := os.Args[1]
	containerName := os.Args[2]

	conf, err := newConfig(os.Args)
	if err != nil {
		fail("Invalid options: %s", err)
	}

	if !conf.JSONOutput {
		_, _ = fmt.Fprintf(os.Stderr, "clair timeout %s\n", conf.ClairTimeout)
		_, _ = fmt.Fprintf(os.Stderr, "docker timeout: %s\n", conf.DockerConfig.Timeout)
	}
	whitelist := &vulnerabilitiesWhitelist{}
	if conf.WhiteListFile != "" {
		if !conf.JSONOutput {
			_, _ = fmt.Fprintf(os.Stderr, "whitelist file: %s\n", conf.WhiteListFile)
		}
		whitelist, err = parseWhitelistFile(conf.WhiteListFile)
		if err != nil {
			fail("Could not parse whitelist file: %s", err)
		}
	} else {
		if !conf.JSONOutput {
			_, _ = fmt.Fprintf(os.Stderr, "no whitelist file\n")
		}
	}

	image, err := docker.NewImage(&conf.DockerConfig)
	if err != nil {
		fail("Can't parse name: %s", err)
	}

	err = image.Pull()
	if err != nil {
		fail("Can't pull image: %s", err)
	}

	output := jsonOutput{
		Vulnerabilities: make(map[string][]*clair.Vulnerability),
	}

	if len(image.FsLayers) == 0 {
		fail("Can't pull fsLayers")
	} else {
		if conf.JSONOutput {
			output.LayerCount = len(image.FsLayers)
		} else {
			fmt.Printf("Analysing %d layers\n", len(image.FsLayers))
		}
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
		fail("Failed to analyze, exiting")
	}

	vsNumber := 0

	numVulnerabilities := len(vulnerabilities)
	vulnerabilities = filterWhitelist(whitelist, vulnerabilities, image.Name)
	numVulnerabilitiesAfterWhitelist := len(vulnerabilities)
	groupBySeverity(vulnerabilities)

	if conf.JSONOutput {
		vsNumber = jsonFormat(conf, output)
	} else {
		if numVulnerabilitiesAfterWhitelist < numVulnerabilities {
			//display how many vulnerabilities were whitelisted
			fmt.Printf("Whitelisted %d vulnerabilities\n", numVulnerabilities-numVulnerabilitiesAfterWhitelist)
		}
		fmt.Printf("Found %d vulnerabilities\n", len(vulnerabilities))
		switch style := conf.FormatStyle; style {
		case "table":
			vsNumber = tableFormat(conf, vulnerabilities)
		default:
			vsNumber = standardFormat(conf, vulnerabilities)
		}
	}

	if conf.ForwardingTargetURL != "" {

		data := Data {
			Vulnerabilities: 	vulnerabilities,
			Container: 			containerName,
			Image: 				imageName,
		}
		marshal, err := json.Marshal(data)
		if err != nil {
			fail("Failed to forward, exiting...")
		}

		forwardVulnerabilities(conf.ForwardingTargetURL, marshal)
	}

	if vsNumber > conf.Threshold {
		os.Exit(1)
	}
}
