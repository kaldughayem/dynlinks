// Package conf holds the structures used across the modules.
package conf

import "C"

// ASInfo holds the AS information loaded from the gen directory specified.
type ASInfo struct {
	// ConfigDir is the configuration directory of that AS.
	ConfigDir string
	// AP is a flag set to true is the AS is the attachment point to the SCION network.
	AP bool
}

// ASInfos is used across the modules to hold configuration values for each AS in the topology.
type ASInfos map[string]ASInfo
