// Package packettale exposes the distribution's canonical license text.
package packettale

import _ "embed"

//go:embed LICENSE
var licenseText string

// LicenseText returns the license distributed with this source tree.
func LicenseText() string { return licenseText }
