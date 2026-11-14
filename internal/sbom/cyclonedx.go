package sbom

import (
	"encoding/json"
	"fmt"
)

// CycloneDX 1.6 constants.
const (
	cycloneDXBOMFormat   = "CycloneDX"
	cycloneDXSpecVersion = "1.6"
	cycloneDXVersion     = 1
	cycloneDXComponent   = "library"
	cycloneDXToolType    = "application"
)

// cdxBOM is the subset of the CycloneDX 1.6 JSON schema this package emits.
type cdxBOM struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     cdxMetadata    `json:"metadata"`
	Components   []cdxComponent `json:"components"`
}

type cdxMetadata struct {
	Timestamp  string        `json:"timestamp"`
	Tools      cdxToolList   `json:"tools"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

// cdxToolList uses the 1.5+ object shape; the array form was removed from the
// 1.6 schema.
type cdxToolList struct {
	Components []cdxTool `json:"components"`
}

type cdxTool struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type cdxComponent struct {
	Type       string        `json:"type"`
	Name       string        `json:"name"`
	Version    string        `json:"version"`
	PURL       string        `json:"purl,omitempty"`
	Properties []cdxProperty `json:"properties,omitempty"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// renderCycloneDX serialises the document as CycloneDX 1.6 JSON.
func (d *Document) renderCycloneDX() ([]byte, error) {
	out := cdxBOM{
		BOMFormat:    cycloneDXBOMFormat,
		SpecVersion:  cycloneDXSpecVersion,
		SerialNumber: d.serialNumber(),
		Version:      cycloneDXVersion,
		Metadata: cdxMetadata{
			Timestamp: d.timestamp(),
			Tools: cdxToolList{Components: []cdxTool{{
				Type:    cycloneDXToolType,
				Name:    d.toolName(),
				Version: d.ToolVersion,
			}}},
			Properties: warningProperties(d.orderedWarnings()),
		},
		Components: make([]cdxComponent, 0, len(d.Packages)),
	}
	for _, p := range d.orderedPackages() {
		out.Components = append(out.Components, cdxComponent{
			Type:       cycloneDXComponent,
			Name:       p.Name,
			Version:    p.Version,
			PURL:       p.PURL,
			Properties: []cdxProperty{dependencyScope(p.Dev)},
		})
	}
	return marshalDocument(out)
}

// warningProperties records coverage gaps in metadata.properties. CycloneDX has
// no comment field, and a property keeps the limitation next to the inventory
// instead of in a log a consumer never sees.
func warningProperties(warnings []string) []cdxProperty {
	if len(warnings) == 0 {
		return nil
	}
	out := make([]cdxProperty, 0, len(warnings))
	for _, warning := range warnings {
		out = append(out, cdxProperty{Name: warningProperty, Value: warning})
	}
	return out
}

// dependencyScope records whether a component is a development dependency.
// Both values are always written so consumers can filter either way.
func dependencyScope(dev bool) cdxProperty {
	scope := scopeProduction
	if dev {
		scope = scopeDevelopment
	}
	return cdxProperty{Name: dependencyScopeProperty, Value: scope}
}

// marshalDocument renders an SBOM as indented JSON with a trailing newline, the
// same convention the report package uses.
func marshalDocument(doc any) ([]byte, error) {
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("sbom: marshal json: %w", err)
	}
	return append(b, '\n'), nil
}
