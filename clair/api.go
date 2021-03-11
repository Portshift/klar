package clair

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/Portshift/klar/types"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/Portshift/klar/docker"
	"github.com/Portshift/klar/utils"
)

// Interface for easier testing
//go:generate $GOPATH/bin/mockgen -destination=./mock_http_client.go -package=clair github.com/Portshift/klar/clair HTTPClient
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type apiV1 struct {
	url    string
	client HTTPClient
}

func newAPIV1(url string, timeout time.Duration) *apiV1 {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = fmt.Sprintf("http://%s", url)
	}
	if strings.LastIndex(url, ":") < 6 {
		url = fmt.Sprintf("%s:6060", url)
	}
	return &apiV1{
		url: url,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (a *apiV1) Push(image *docker.Image) error {
	for i := 0; i < len(image.FsLayers); i++ {
		layer := newLayer(image, i)
		if err := a.pushLayer(layer); err != nil {
			return err
		}
	}
	return nil
}

func (a *apiV1) pushLayer(layer *layer) error {
	envelope := layerEnvelope{Layer: layer}
	reqBody, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("can't serialze push request: %s", err)
	}
	url := fmt.Sprintf("%s/v1/layers", a.url)
	request, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("can't create a push request: %s", err)
	}
	request.Header.Set("Content-Type", "application/json")
	utils.DumpRequest(request)
	response, err := a.sendWithRetries(request)
	if err != nil {
		return fmt.Errorf("can't push layer to Clair: %s", err)
	}
	utils.DumpResponse(response)
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("can't read clair response : %s", err)
	}
	if response.StatusCode != http.StatusCreated {
		var lerr layerError
		err = json.Unmarshal(body, &lerr)
		if err != nil {
			return fmt.Errorf("can't even read an error message: %s", err)
		}
		return fmt.Errorf("push error %d: %s. %w", response.StatusCode, string(body), types.ErrorClairServer)
	}
	return nil
}

const maxRetries = 5
const retryIntervalSec = 1

func (a *apiV1) sendWithRetries(request *http.Request) (*http.Response, error) {
	response, err := a.client.Do(request)
	if err != nil {
		log.Debugf("Failed to send request, retrying for %v times", maxRetries)
		timer := time.After(time.Duration(maxRetries) * time.Second)
		ticker := time.NewTicker(time.Duration(retryIntervalSec) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-timer:
				return nil, fmt.Errorf("failed to send request after %v retries", maxRetries)
			case <-ticker.C:
				log.Debugf("Retrying to send request")
				response, err := a.client.Do(request)
				if err == nil {
					log.Debugf("Successfully sent request")
					return response, nil
				}
			}
		}
	}
	return response, nil
}

func (a *apiV1) Analyze(image *docker.Image) ([]*Vulnerability, error) {
	url := fmt.Sprintf("%s/v1/layers/%s?vulnerabilities", a.url, image.AnalyzedLayerName())
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("can't create an analyze request: %s", err)
	}
	utils.DumpRequest(request)
	response, err := a.sendWithRetries(request)
	if err != nil {
		return nil, err
	}
	utils.DumpResponse(response)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(response.Body)
		return nil, fmt.Errorf("analyze error %d: %s", response.StatusCode, string(body))
	}
	var envelope layerEnvelope
	if err = json.NewDecoder(response.Body).Decode(&envelope); err != nil {
		return nil, err
	}
	var vs []*Vulnerability
	for _, f := range envelope.Layer.Features {
		for _, v := range f.Vulnerabilities {
			v.FeatureName = f.Name
			v.FeatureVersion = f.Version
			//the for loop uses the same variable for "v", reloading with new values
			//since we are appending a pointer to the variable to the slice, we need to create a copy of the struct
			//otherwise the slice winds up with multiple pointers to the same struct
			vulnerability := v
			// AddedBy will be in the form of: aaabbb where image.Digest is sha256:aaa and layer hash is bbb. Need to strip image hash prefix
			vulnerability.LayerHash = strings.TrimPrefix(f.AddedBy, docker.TrimDigest(image.Digest))
			vs = append(vs, &vulnerability)
		}
	}
	return vs, nil
}
