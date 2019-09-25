package conf

import (
	"fmt"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
	"path"
)

// Link instance holds the link identifiers; ports, ASes, and ifids.
// It also holds the properties to be applied for that link.
// It represents a single link and is used in main.go to build the links structure or pass them to
// the collector module.
type Link struct {
	// ASA is the first AS attached to this link
	ASA string
	// IfidA is the ID of the interface at AS A
	IfidA common.IFIDType
	// PortA is the port at AS A
	PortA uint16
	// ASB is the AS on the other end of this link "AS B"
	ASB string
	// IfidB is the interface ID at AS B
	IfidB common.IFIDType
	// PortB is the port at AS B
	PortB uint16
	// Type is the link type from AS A point of view
	Type proto.LinkType
	// Properties to be applied to the link
	Properties LinkProperties
}

// Links map link names' to their information
type Links map[string]*Link

// PrintLinks prints the Links identifiers (ports, ifids, ASes and Type)
func (links *Links) PrintLinks() {
	var info string
	for id, l := range *links {
		info += fmt.Sprintf("- Link ID: %s\n", id)
		info += fmt.Sprintf("\t AS A: 			%s\n", l.ASA)
		info += fmt.Sprintf("\t Interface A: 	%d\n", l.IfidA)
		info += fmt.Sprintf("\t Port A: 		%d\n", l.PortA)
		info += fmt.Sprintf("\t AS B: 			%s\n", l.ASB)
		info += fmt.Sprintf("\t Interface B: 	%d\n", l.IfidB)
		info += fmt.Sprintf("\t Port B:	 	%d\n", l.PortB)
		info += fmt.Sprintf("\t Type: 			%s\n", l.Type.String())
	}

	fmt.Println(info)
}

// Builds the links structure based on the topology.json file of each AS in asInfos
func BuildLinks(links Links, asInfos map[string]ASInfo) error {
	for asID, asInfo := range asInfos {
		// Load topology file of AS
		topo, err := topology.LoadFromFile(path.Join(asInfo.ConfigDir, env.DefaultTopologyPath))
		if err != nil {
			return common.NewBasicError("Loading topology file", err)
		}

		for ifid, info := range topo.IFInfoMap {
			l := &Link{
				ASA:        asID,
				IfidA:      ifid,
				PortA:      info.Local.IPv4.PublicOverlay.L4().Port(),
				ASB:        info.ISD_AS.String(),
				IfidB:      info.RemoteIFID,
				PortB:      info.Remote.L4().Port(),
				Type:       info.LinkType,
				Properties: DefaultProperties(),
			}

			exists, linkName := LinkExists(*l, links)
			if exists {
				links[linkName].IfidB = ifid
			} else {
				linkName := asID + "_" + info.ISD_AS.String()
				links[linkName] = l
			}
		}
	}

	return nil
}

// LinkExists checks links so we don't add a link twice. Returns true and link name if a matching link in
// links is found, otherwise returns false and an empty string
func LinkExists(newLink Link, links Links) (bool, string) {
	for name, info := range links {
		name1 := fmt.Sprintf("%s_%s", newLink.ASA, newLink.ASB)
		// Try the name the other way around
		name2 := fmt.Sprintf("%s_%s", newLink.ASB, newLink.ASA)
		possibleNames := []string{name1, name2}

		for _, newName := range possibleNames {
			if newName == name {
				if info.PortA == newLink.PortB || info.PortB == newLink.PortA {
					return true, newName
				}
			}
		}
	}
	return false, ""
}
