package forwarding

import (
	"github.com/optiopay/klar/clair"
)

type ContextualVulnerability struct {
	Vulnerability *clair.Vulnerability `json:"vulnerability"`
	Pod           string               `json:"pod,omitempty"`
	Container     string               `json:"container,omitempty"`
	Image         string               `json:"image,omitempty"`
	Namespace     string               `json:"namespace,omitempty"`
}
