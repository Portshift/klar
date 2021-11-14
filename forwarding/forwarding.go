package forwarding

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/Portshift/klar/docker"
	"github.com/Portshift/klar/types"
	grype_models "github.com/anchore/grype/grype/presenter/models"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
)

type ImageVulnerabilities struct {
	Vulnerabilities *grype_models.Document   `json:"vulnerability"`
	LayerCommands   []*docker.FsLayerCommand `json:"layerCommands"`
	Image           string                   `json:"image"`
	Success         bool                     `json:"success"`
	ScanUUID        string                   `json:"scanuuid"`
	ScanErr         *types.ScanError         `json:"scanError"`
}

func SendScanResults(resultServicePath string, scanResults *ImageVulnerabilities) error {
	if len(resultServicePath) == 0 {
		log.Infof("No result service path provided")
		return nil
	}

	jsonBody, err := json.Marshal(scanResults)
	if err != nil {
		return fmt.Errorf("failed marshal results: %v", err)
	}

	req, err := http.NewRequest("POST", resultServicePath, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to forward vulnerabilities: %v", err)
	}
	req.Close = true
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		if resp != nil {
			log.Errorf("response Status: %s", resp.Status)
		}
		return err
	}
	defer resp.Body.Close()

	log.Infof("response Status: %s", resp.Status)
	log.Debugf("response Headers: %s", resp.Header)
	respBody, _ := ioutil.ReadAll(resp.Body)
	log.Debugf("response Body %s:", string(respBody))

	return nil
}
