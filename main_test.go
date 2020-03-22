package main

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/Portshift/klar/clair"
)

func mockVulnerability(name string) *clair.Vulnerability {
	return &clair.Vulnerability{name, "", "", "", "", nil, "", nil, "", ""}
}
