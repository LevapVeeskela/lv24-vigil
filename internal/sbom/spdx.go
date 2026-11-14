package sbom

import (
	"strconv"
	"strings"
)

// SPDX 2.3 constants.
const (
	spdxVersion          = "SPDX-2.3"
	spdxDocumentID       = "SPDXRef-DOCUMENT"
	spdxDataLicense      = "CC0-1.0"
	spdxNoAssertion      = "NOASSERTION"
	spdxPackageIDPrefix  = "SPDXRef-Package-"
	spdxReferencePurl    = "purl"
	spdxReferencePackage = "PACKAGE-MANAGER"
)

// spdxDocument is the subset of the SPDX 2.3 JSON schema this package emits.
type spdxDocument struct {
	SPDXID            string           `json:"SPDXID"`
	SPDXVersion       string           `json:"spdxVersion"`
	CreationInfo      spdxCreationInfo `json:"creationInfo"`
	Name              string           `json:"name"`
	DataLicense       string           `json:"dataLicense"`
	DocumentNamespace string           `json:"documentNamespace"`
	DocumentComment   string           `json:"documentComment,omitempty"`
	Packages          []spdxPackage    `json:"packages"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	LicenseConcluded string            `json:"licenseConcluded"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// renderSPDX serialises the document as SPDX 2.3 JSON.
//
// filesAnalyzed is false because the document lists dependencies without
// listing their files; without it SPDX would require a package verification
// code that cannot be produced here.
func (d *Document) renderSPDX() ([]byte, error) {
	out := spdxDocument{
		SPDXID:      spdxDocumentID,
		SPDXVersion: spdxVersion,
		CreationInfo: spdxCreationInfo{
			Created:  d.timestamp(),
			Creators: []string{d.creator()},
		},
		Name:              d.documentName(),
		DataLicense:       spdxDataLicense,
		DocumentNamespace: d.documentNamespace(),
		DocumentComment:   spdxDocumentComment(d.orderedWarnings()),
		Packages:          make([]spdxPackage, 0, len(d.Packages)),
	}
	for i, p := range d.orderedPackages() {
		pkg := spdxPackage{
			SPDXID:           spdxPackageIDPrefix + strconv.Itoa(i+1),
			Name:             p.Name,
			VersionInfo:      p.Version,
			DownloadLocation: spdxNoAssertion,
			FilesAnalyzed:    false,
			LicenseConcluded: spdxNoAssertion,
		}
		if p.PURL != "" {
			pkg.ExternalRefs = []spdxExternalRef{{
				ReferenceCategory: spdxReferencePackage,
				ReferenceType:     spdxReferencePurl,
				ReferenceLocator:  p.PURL,
			}}
		}
		out.Packages = append(out.Packages, pkg)
	}
	return marshalDocument(out)
}

// creator renders the SPDX "Tool: name-version" creator string.
func (d *Document) creator() string {
	creator := "Tool: " + d.toolName()
	if d.ToolVersion != "" {
		creator += "-" + d.ToolVersion
	}
	return creator
}

// spdxDocumentComment records coverage gaps. SPDX 2.3 has no warning field, and
// documentComment is the free-text field a consumer reads with the packages.
func spdxDocumentComment(warnings []string) string {
	return strings.Join(warnings, "\n")
}
