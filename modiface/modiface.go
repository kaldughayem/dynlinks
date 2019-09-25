// Package modiface modifies a single interface in a given AS.
// The package would first initialize a SCION connection to retrieve the ifStates from the beacon server.
// Then if the revoke metric is set revokes the interface with the given interface ID by setting its revoked flag to
// true, and creates a Revoker to revoke it. If the token revocation method was chosen, then modiface would first
// initialize a trustStore to create a sign from the AS keys.
//
// Otherwise, when the revoke metric is not set, it would apply the Properties passed by the caller on the given link.
package modiface

import (
	"fmt"
	"github.com/kaldughayem/dynlinks/conf"
	"github.com/kaldughayem/dynlinks/utils"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"os"
	"path/filepath"
	"sync"
)

var (
	connInitLock sync.Mutex
	tcLock       sync.Mutex
)

// Config is the configuration values for a modiface instance.
type Config struct {
	ID     string
	Sciond env.SciondClient
	// Path to the dispatcher
	Dispatcher string
	// The IA of the AS to be modified
	ActiveAS addr.IA
	// The interface ID in that AS to nbe modified
	IFID common.IFIDType
	// The address to use to send requests to other scion services
	LocalAddr *snet.Addr
	// The information for other ASes running on this device and their gen directories are present
	ASInfos map[string]conf.ASInfo
	// The Properties to apply to the interface.
	Properties *conf.LinkProperties
	// Caller's ReturnChan channel.
	ReturnChan chan struct{}
	// ExitChan is a channel where a signal to ExitChan the routine from the caller is received.
	ExitChan chan struct{}

	// configDir for loading extra files (keys, certificates, and topology.json)
	configDir string
	// topologyPath is the file path for the local topology JSON file.
	topologyPath string
	// topology is the loaded topology file.
	topology *topology.Topo
	// True when the active configuration is for the attachment point AS
	ap bool
}

func (cfg *Config) setFiles() error {
	if cfg.configDir == "" {
		return nil
	}
	info, err := os.Stat(cfg.configDir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return common.NewBasicError(
			fmt.Sprintf("%v is not a directory", cfg.configDir), nil)
	}
	if cfg.topologyPath == "" {
		cfg.topologyPath = filepath.Join(cfg.configDir, env.DefaultTopologyPath)
	}
	return nil
}

func setTopology(cfg *Config) error {
	if err := cfg.setFiles(); err != nil {
		return err
	}
	topo, err := topology.LoadFromFile(cfg.topologyPath)
	if err != nil {
		return err
	}
	cfg.topology = topo
	return nil
}

// Modiface is an interface modifier instance, it applies the Properties parsed to the specified interface "ifid".
type Modiface struct {
	// The configuration file for this instance of Modiface.
	cfg *Config
	// SCION connection to pass to revoker.
	log log.Logger
	wg  sync.WaitGroup
}

// NewModiface creates a new Modiface instance.
func NewModiface(config *Config) *Modiface {
	m := &Modiface{
		cfg: config,
	}
	return m
}

// Run is the main processing loop for the Modiface instance.
func (m *Modiface) Run() {
	m.log = log.New("modiface", m.cfg.ID)
	if err := m.setup(); err != nil {
		m.log.Error("Setup failed", "err", err)
		m.cfg.ReturnChan <- struct{}{}
		return
	}

	go m.exitFunction()

	// Check if we should revoke the link
	if m.cfg.Properties.Revoke {
		m.wg.Add(1)
		go func(wg *sync.WaitGroup) {
			// Create new revoker
			r := NewRevoker(m.cfg)
			// Run the revoker to revoke the interface using the specified method
			r.Run()
			wg.Done()
		}(&m.wg)
	}

	// Check if Properties are set
	metricsSet := m.cfg.Properties.Delay != 0 || m.cfg.Properties.Rate != "" || m.cfg.Properties.Corrupt != 0 ||
		m.cfg.Properties.Loss != 0 || m.cfg.Properties.Duplicate != 0

	if metricsSet {
		m.wg.Add(1)
		// Apply deterioration Properties if they are set
		if err := m.runTcCommand(); err != nil {
			m.log.Error("Running tc command", "err", err)
		}
	}

	// Wait for revokers to return or for the exit signal
	m.wg.Wait()
	m.cfg.ReturnChan <- struct{}{}
}

// exitFunction listens on the exit channel and waits for a signal to terminate
// this go routine and revert it's changes.
func (m *Modiface) exitFunction() {
	<-m.cfg.ExitChan
	// Check if Properties are set
	metricsSet := m.cfg.Properties.Delay != 0 || m.cfg.Properties.Rate != "" || m.cfg.Properties.Corrupt != 0 ||
		m.cfg.Properties.Loss != 0 || m.cfg.Properties.Duplicate != 0
	if metricsSet {
		if err := revertTcChanges(m.cfg); err != nil {
			m.log.Error("Reverting changes", "err", err)
		} else {
			m.log.Debug("Reverted changes successfully")
		}
		m.wg.Done()
	}
}

// Parses the link Properties to tcconfig and runs the command based on those parameters for
// the specified interface.
func (m *Modiface) runTcCommand() error {
	args := fmt.Sprintf("sudo tcset --add --delay %fs --delay-distro %fs --loss %f --corrupt %f --duplicate "+
		"%f --reordering %f", m.cfg.Properties.Delay.Seconds(), m.cfg.Properties.DelayDist.Seconds(),
		m.cfg.Properties.Loss, m.cfg.Properties.Corrupt, m.cfg.Properties.Duplicate,
		m.cfg.Properties.Reorder)

	if m.cfg.Properties.Rate != "" {
		args = args + " --rate " + m.cfg.Properties.Rate
	}

	if err := utils.BuildTcCommand(args, *m.cfg.topology, m.cfg.ActiveAS.String(),
		m.cfg.ASInfos, m.cfg.IFID); err != nil {
		return common.NewBasicError("Running tcconfig command", err)
	}

	m.log.Debug("Applying link deterioration properties")
	return nil
}

// setup is the main setup function, Loads the topology file and sets it as the current active topology, sets the
// current AS control address and ActiveAS, starts the initializes the sciond connection, and sets the core AS
// addresses.
func (m *Modiface) setup() error {
	// Initialize the configuration file
	if err := initConfig(m.cfg); err != nil {
		return common.NewBasicError("Configuration loading failed", err)
	}

	// check the Properties again, already checked in main but check again here for sanity
	if err := utils.ValidateProperties(m.cfg.Properties); err != nil {
		return common.NewBasicError("Validating Properties", err)
	}

	// set the active AS specified by the user and load its keys
	m.setActiveAS()

	// Load topology and set it as the current running topology
	if err := setTopology(m.cfg); err != nil {
		return common.NewBasicError("Initializing the general configuration parameters", err)
	}

	// Check if specified interface exists in that AS's topology
	if !interfaceInTopo(m.cfg.IFID, *m.cfg.topology) {
		return common.NewBasicError("Interface not found in topology.json file", nil, "topo",
			m.cfg.topologyPath)
	}

	// initialize the sciond path and connection timeout if not specified in General file
	env.InitSciondClient(&m.cfg.Sciond)

	//m.log.Trace("Setup finished")
	return nil
}

// SetActiveAS sets the configuration values for the active AS's, and loads the files needed.
func (m *Modiface) setActiveAS() {
	m.cfg.configDir = m.cfg.ASInfos[m.cfg.ActiveAS.String()].ConfigDir
	m.cfg.ap = m.cfg.ASInfos[m.cfg.ActiveAS.String()].AP

	if m.cfg.ap && m.cfg.IFID == 1 {
		m.log.Warn("Modifying connection to SCION attachment point")
	}
}

func initConfig(cfg *Config) error {
	if cfg.ID == "" {
		return common.NewBasicError("ID must be set", nil)
	}

	if err := utils.CheckAndCreateDir("cache"); err != nil {
		return err
	}

	return nil
}

// interfaceInTopo checks if interface ifid exists in the topology.json file loaded.
func interfaceInTopo(ifid common.IFIDType, topo topology.Topo) bool {
	for i := range topo.IFInfoMap {
		if ifid == i {
			return true
		}
	}
	return false
}

// revertTcChanges deletes the tc rules added according to the passed cfg parameter.
func revertTcChanges(cfg *Config) error {
	tcLock.Lock()
	args := "sudo tcdel"

	if err := utils.BuildTcCommand(args, *cfg.topology, cfg.ActiveAS.String(), cfg.ASInfos, cfg.IFID); err != nil {
		return common.NewBasicError("Reverting changes", err)
	}
	//log.Debug("Reverted link deterioration changes", "AS", cfg.ActiveAS, "IFID", cfg.IFID)
	tcLock.Unlock()
	return nil
}
