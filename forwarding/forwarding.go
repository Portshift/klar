package forwarding

import (
	"github.com/Portshift-Admin/klar/clair"
)

type ImageVulnerabilities struct {
	Vulnerabilities []*clair.Vulnerability `json:"vulnerability"`
	Image           string                 `json:"image,omitempty"`
}
