package forwarding

import (
	"github.com/Portshift-Admin/klar/clair"
)

type ContextualVulnerability struct {
	Vulnerability *clair.Vulnerability `json:"vulnerability"`
	Image         string               `json:"image,omitempty"`
}
