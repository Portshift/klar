package format

import (
	"fmt"
	"github.com/Portshift/klar/clair"
	"github.com/Portshift/klar/config"
)

var store = make(map[string][]*clair.Vulnerability)

var SeverityStyle = map[string]string{
	"Defcon1":    "\033[1;31m%s\033[0m",
	"Critical":   "\033[1;31m%s\033[0m",
	"High":       "\033[0;31m%s\033[0m",
	"Medium":     "\033[0;33m%s\033[0m",
	"Low":        "\033[0;94m%s\033[0m",
	"Negligible": "\033[0;94m%s\033[0m",
	"Unknown":    "\033[0;97m%s\033[0m",
}

func groupBySeverity(vs []*clair.Vulnerability) {
	for _, v := range vs {
		sevRow := vulnerabilitiesBySeverity(v.Severity, store)
		store[v.Severity] = append(sevRow, v)
	}
}

func vulnerabilitiesBySeverity(sev string, store map[string][]*clair.Vulnerability) []*clair.Vulnerability {
	items, found := store[sev]
	if !found {
		items = make([]*clair.Vulnerability, 0)
		store[sev] = items
	}
	return items
}

func PrintVulnerabilities(conf *config.Config, vs []*clair.Vulnerability) int {
	groupBySeverity(vs)
	vsNumber := 0
	iteratePriorities(config.Priorities[0], func(sev string) { fmt.Printf("%s: %d\n", sev, len(store[sev])) })
	fmt.Printf("\n")

	iteratePriorities(conf.ClairOutput, func(sev string) {
		for _, v := range store[sev] {
			fmt.Printf("%s: [%s] \nFound in: %s [%s]\nFixed By: %s\n%s\n%s\n", v.Name, v.Severity, v.FeatureName,
				v.FeatureVersion, v.FixedBy, v.Description, v.Link)
			fmt.Println("-----------------------------------------")
			if conf.IgnoreUnfixed {
				if v.FixedBy != "" {
					vsNumber++
				}
			} else {
				vsNumber++
			}
		}
	})
	return vsNumber
}

func iteratePriorities(output string, f func(sev string)) {
	filtered := true
	for _, sev := range config.Priorities {
		if filtered {
			if sev != output {
				continue
			} else {
				filtered = false
			}
		}

		if len(store[sev]) != 0 {
			f(sev)
		}
	}
}
