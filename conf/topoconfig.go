package conf

import (
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/topology"
)

// TopoConfig is the topology YAML configuration parsed from the user, a more
// detailed description can be found in the file itself.
type TopoConfig struct {
	MTU         string `yaml:"MTU"`
	GenDir      string `yaml:"gen-dir"`
	NetworkName string `yaml:"network-name"`
	Subnet      string
	Defaults    defaults
	ASes        ASMap `yaml:"ASes"`
	Links       []TopoLink
}

type defaults struct {
	Zookeepers Zookeepers
}

// Zookeepers is a mpa of Zookeeper instances
type Zookeepers map[int]Zookeeper

// Zookeeper holds the port and address of the zookeeper instance
// to connect all containers and host to.
type Zookeeper struct {
	Addr string
	Port int
}

// ASMap is a map of AS information
type ASMap map[string]*AS

// AS holds all the information required for one AS to start a new topology.
// Only AP is retrieved from the topology file the rest are set during execution.
type AS struct {
	Topo  *topology.RawTopo
	IfID  common.IFIDType
	IP    string
	APStr string `yaml:"AP"`
	Info  *ASInfo
	MTU   int `yaml:"mtu"`
}

type TopoLink struct {
	A           string
	B           string
	LinkAtoB    string            `yaml:"linkAtoB"`
	Overlay     string            `yaml:"overlay"`
	MTU         int               `yaml:"mtu"`
	Bandwidth   int               `yaml:"bw"`
	BindOverlay *topology.RawAddr `yaml:",omitempty"`
}
