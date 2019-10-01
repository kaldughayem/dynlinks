package modiface

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kaldughayem/dynlinks/ifstate"
	"github.com/kaldughayem/dynlinks/utils"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/truststorage"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/proto"
)

// RevocationType to apply to the interface
type RevocationType string

const (
	// RevocationToken creates signed revocation info, then sends ifState updates to the local and to the parent AS's
	// border routers and path servers.
	RevocationToken RevocationType = "token"
	// BlockPackets blocks the overlay traffic going through the SCION interface using tcconfig
	BlockPackets RevocationType = "block"
	// ModifyTopology removes the interface from the local border router topology.
	ModifyTopology RevocationType = "topo"
)

// DefaultRevOverlap specifies the default for how long before the expiry of an existing revocation the revoker can
// reissue a newIFID revocation.
const DefaultRevOverlap = path_mgmt.MinRevTTL

var (
	// topoLock is a lock for editing the topology file
	topoLock sync.Mutex
)

// Revoker is in charge of revoking a specified interface with ID "ifid" using a certain method of revocation
// based on "method". There are three methods to revoke an interface:
// 1. "token" revocation method: revoker loads the interface from the ifState package and sets its revocation info,
// 		creates signed revocation info based on the information from the loaded state, then starts sending messages:
// 			- The signed revocation info to the local beacon server
//			- ifState update message to the local border routers and path servers, and its parent's path server to
//				remove the path segments from there as well.
//		When the revoker exits then it has nothing to revert when using this method, but stops sending the messages.
// 2. "block": revoker issues tc command to block egress and ingress packets from/to overlay address of the interface
//		by setting the loss on those packets by 100%. When the revoker exits, it deletes the tc rule made on that
//		interface.
// 3. "topo": find the interface in the AS's border router's topology.json file saves a copy of the topology in
// 		"topoBackUP" and removes the interface from the topology file. When the revoker exits then it restores the
//		old topology.
// If the revocation period is set, then the revoker would revoke the interface for one period, then revert the changes,
// wait fo one period then revokes the interface again.
type Revoker struct {
	// General is used to retrieve the local address and the signing keys if token revocation method is chosen
	cfg *Config
	// Sign to sign the revocation info for an interface when that method is chosen
	//Sign *proto.SignS
	Sign infra.Signer
	// states are the Interface states used with the token method
	states   ifstate.IfStates
	snetConn snet.Conn

	// The revocation method to be applied
	method RevocationType
	// period of a single revocation cycle, when period=0 then the revocation is continuous
	period time.Duration
	// probability that the interface would be revoked during a a single period
	probability float64

	// keyConf contains the AS level keys.
	keyConf *keyconf.Conf
	// store is the trust store.
	store *trust.Store
	//  trustDB is the trust DB.
	trustDB     trustdb.TrustDB
	trustDBConf truststorage.TrustDBConf

	// stop is a flag to break from the token revocation method loop and stop sending ifState updates and signed
	// revocation info.
	stop bool
	// topology backup for when using the topology revocation method
	topoIfaceBackUp topology.RawBRIntf

	timerChan chan struct{}
	// lock for the stop flag
	stopLock sync.Mutex
	wg       sync.WaitGroup
	log      log.Logger
}

// NewRevoker creates a new revoker object.
func NewRevoker(config *Config) *Revoker {
	r := &Revoker{
		cfg:         config,
		probability: config.Properties.RevocationProb,
		period:      config.Properties.RevocationPeriod,
		method:      (RevocationType)(strings.ToLower(config.Properties.RevocationMethod)),
		stop:        false,
	}
	return r
}

// Run is the main processing loop for the revoker. Then depending on the
// revocation method revoke that interface to stop all incoming and outgoing
// communication.
func (r *Revoker) Run() {
	var err error
	r.wg.Add(1)

	r.timerChan = make(chan struct{})
	go func() {
		<-r.cfg.ExitChan
		r.stopLock.Lock()
		r.stop = true
		r.stopLock.Unlock()
		r.wg.Done()
	}()

	// Setup the logger for the revoker
	r.log = log.New("revoker", r.cfg.ID)

	defer func() {
		if err = r.revertChanges(); err != nil {
			r.log.Error("Reverting changes", "err", err)
		}
	}()

	switch r.method {
	case RevocationToken:
		if err := r.tokenRevocation(); err != nil {
			r.log.Crit("Sending revocation tokens", "err", err)
			return
		}

	case ModifyTopology:
		r.simpleRevocationProcess(r.modifyTopo)

	case BlockPackets:
		r.simpleRevocationProcess(r.blockPackets)

	default:
		r.log.Error("Unrecognized revocation method", "method", r.method)
	}

}

// simpleRevocationProcess is the revocation process where if you have a period set, the:
// - Revoke the interface using the function
// - Wait for period
// - Revert changes and wait for the same period again
//
// When no period is set, it just waits for wait group wg which would be decremented
// by the exit routine.
//
// When a probability is set, for every period a random number is generated. If it is
// lower the the set probability, the interface will be revoked in that period.
func (r *Revoker) simpleRevocationProcess(revocationFunction func() error) {
	var err error
	for !r.getStop() {
		if r.probability < 100 {
			if rand.Float64() < (r.probability / 100) {
				err = revocationFunction()
			}
		} else {
			err = revocationFunction()
		}

		if err != nil {
			r.log.Error("Revoking interface", "method", r.method, "err", err)
		} else {
			r.log.Info("Revoked interface", "AS", r.cfg.ActiveAS, "IFID", r.cfg.IFID, "method", r.method)
		}

		if r.period > 0 {
			// If period is set, revert changes then start again
			time.Sleep(r.period)
			if err := r.revertChanges(); err != nil {
				r.log.Error("Reverting changes", "err", err)
			}

			time.Sleep(r.period)
		} else {
			// Wait for exit signal to revert changes
			r.wg.Wait()
		}
	}
}

// Revoke interface by continuously sending PathMgmt messages to local Border
// Routers and Path Servers (IfState update message with signed revocation info).
//
// It would perform setup of the Sign and the snetConn to get interface states
// before starting to send the IfState updates with the revocation info.
//
// It is different from the simple revocation period in that it uses a timer
// to toggle a variable called "send" value. When send is set, it will send a
// token.
func (r *Revoker) tokenRevocation() error {
	var err error

	if err = r.setupTokenRevocation(); err != nil {
		return common.NewBasicError("Setting up token revocation", err)
	}
	// Load the interface and set its state to inactive (to send to path server and border router)
	// and revoked (for internal use to not send IFState updates for interfaces we did not revoke)
	intf, ok := r.states[r.cfg.IFID]
	if !ok {
		return common.NewBasicError("Interface not found in ifStates structure",
			nil, "ifid", r.cfg.IFID)
	}
	intf.Revoked = true

	pathServer, err := utils.SetupSVCAddress(addr.SvcPS, r.cfg.LocalAddr, r.cfg.ActiveAS, r.cfg.topology)
	if err != nil {
		return common.NewBasicError("Setting up path server address", err)
	}

	borderRouter := &snet.Addr{
		IA:   r.cfg.ActiveAS,
		Host: r.cfg.topology.IFInfoMap[r.cfg.IFID].CtrlAddrs.IPv4.PublicAddr(),
	}

	if err := utils.SetupAddress(r.cfg.LocalAddr, borderRouter); err != nil {
		return common.NewBasicError("Setting up border router address", err)
	}

	r.sendRevocationTokens(intf, pathServer, borderRouter)
	return nil
}

func (r *Revoker) sendRevocationTokens(intf *ifstate.IfState, pathServer, borderRouter *snet.Addr) {
	send := true
	if r.period > 0 {
		go r.toggleFlag(&send, r.period)
	}

	for !r.getStop() {
		if err := r.issueRevocation(intf); err != nil {
			log.Error("Issuing revocation", "err", err)
			continue
		}

		if send {
			if r.probability < 100 {
				if rand.Float64() < (r.probability / 100) {
					r.sendIfStateUpdates(pathServer, borderRouter, r.states)
				}
			} else {
				r.sendIfStateUpdates(pathServer, borderRouter, r.states)
			}
			time.Sleep(time.Millisecond * 500)
		} else {
			// wait for signal from the toggleFlag routine that the send flag is true
			<-r.timerChan
		}
	}
}

func (r *Revoker) toggleFlag(flag *bool, period time.Duration) {
	timer := time.NewTimer(period)
	for !r.getStop() {
		if *flag {
			r.log.Info("Revoking interface", "AS", r.cfg.ActiveAS, "IFID", r.cfg.IFID, "method", r.method)
			<-timer.C
		} else {
			r.log.Info("Reverted changes", "AS", r.cfg.ActiveAS, "IFID", r.cfg.IFID, "method", r.method)
			<-timer.C
			r.timerChan <- struct{}{}
		}
		*flag = !*flag
		timer.Reset(period)
	}
}

// sendIfStateUpdates sends IfState updates to the local and upstream
// path servers, and to the local border router.
func (r *Revoker) sendIfStateUpdates(localPathServer, localBorderRouter *snet.Addr, states ifstate.IfStates) {
	// Send to AP PS to remove these paths and forward the revocations to the core path server
	addresses := []*snet.Addr{localPathServer, localBorderRouter}

	for _, info := range r.cfg.topology.IFInfoMap {
		if info.LinkType == proto.LinkType_parent {
			parentPathServer, err := utils.SetupSVCAddress(addr.SvcPS, r.cfg.LocalAddr, info.ISD_AS, r.cfg.topology)
			if err != nil {
				r.log.Error("Setting up AP (host) Path server address", "err", err)
				return
			}
			addresses = append(addresses, parentPathServer)
		}
	}

	for _, address := range addresses {
		if err := r.sendIfStates(address, states); err != nil {
			r.log.Error("Sending IFState update", "dst", address.String(), "err", err)
			return
		}
	}

}

// buildSignedRev creates a signed revocation for the interface r.General.IFID
func (r *Revoker) buildSignedRev() (*path_mgmt.SignedRevInfo, error) {
	now := util.TimeToSecs(time.Now())
	revInfo := &path_mgmt.RevInfo{
		IfID:         r.cfg.IFID,
		RawIsdas:     r.cfg.topology.ISD_AS.IAInt(),
		LinkType:     r.cfg.topology.IFInfoMap[r.cfg.IFID].LinkType,
		RawTimestamp: now,
		// multiplied it by 2 to reach min TTL for BS TTL=20
		RawTTL: uint32(path_mgmt.MinRevTTL.Seconds() * 2),
	}

	return path_mgmt.NewSignedRevInfo(revInfo, r.Sign)
}

// hasValidRevocation check if the interface has a valid signed revocation information
func (r *Revoker) hasValidRevocation(intf *ifstate.IfState) bool {
	srev := intf.SRevInfo
	if srev != nil {
		rev, err := srev.RevInfo()
		return err == nil && rev.RelativeTTL(time.Now()) >= DefaultRevOverlap
	}
	return false
}

// issueRevocation creates signed revocations (if they do not exist
// or expired) for the interfaces to be revoked.
func (r *Revoker) issueRevocation(intf *ifstate.IfState) error {
	if !r.hasValidRevocation(intf) {
		//r.log.Trace("Generating SRevInfo for interface", "ifid", r.General.IFID)
		var err error
		var srev *path_mgmt.SignedRevInfo
		srev, err = r.buildSignedRev()
		if err != nil {
			return common.NewBasicError("Failed to create revocation", err, "ifid", r.cfg.IFID)
		}
		if err := intf.Revoke(srev); err != nil {
			return common.NewBasicError("Revoking interface", err, "ifid", r.cfg.IFID)
		}
	}
	return nil
}

// sendIfStates sends ifStateUpdate messages to the dstAddress
func (r *Revoker) sendIfStates(dstAddress *snet.Addr, states ifstate.IfStates) error {
	stateInfos, err := ifstate.BuildIFStatesUpdate(states, r.cfg.topology)
	if err != nil {
		return common.NewBasicError("Building IFState Updates", err)

	}

	cpld, err := ctrl.NewPathMgmtPld(stateInfos, nil, nil)
	if err != nil {
		return common.NewBasicError("Generating IFState Update Ctrl payload", err)

	}

	scpld, err := cpld.SignedPld(infra.NullSigner)
	if err != nil {
		return common.NewBasicError("Generating IFState Update signed Ctrl payload", err)
	}

	pld, err := scpld.PackPld()
	if err != nil {
		return common.NewBasicError("Packing IFState Update Ctrl payload", err)
	}

	if _, err := r.snetConn.WriteToSCION(pld, dstAddress); err != nil {
		return common.NewBasicError("Writing IFState", err, "dst", dstAddress)
	}

	// XXX uncomment for debugging
	//r.log.Trace("Sent IFState update", "dst", dstAddress)
	return nil
}

// modifyTopo removes interface with ifid from the border router topology
func (r *Revoker) modifyTopo() error {
	var err error
	// Need the Border router ID/name which belongs to that interface to delete it from there in the topology struct
	brID := r.cfg.topology.IFInfoMap[r.cfg.IFID].BRName
	// Get the BR name that has that interface, and modify it's topology
	file := filepath.Join(brID, env.DefaultTopologyPath)
	topoPath := filepath.Join(filepath.Dir(r.cfg.configDir), file)
	r.topoIfaceBackUp, err = deleteInterfaceFromTopo(brID, topoPath, r.cfg.IFID)
	if err != nil {
		return common.NewBasicError("Modifying border router topology", err)
	}

	for _, bs := range r.cfg.topology.BSNames {
		file = filepath.Join(bs, env.DefaultTopologyPath)
		topoPath := filepath.Join(filepath.Dir(r.cfg.configDir), file)
		_, err = deleteInterfaceFromTopo(brID, topoPath, r.cfg.IFID)
		if err != nil {
			return common.NewBasicError("Modifying beacon service topology", err)
		}
	}
	// Reloads configuration on all of the AS's beacon services, and the modified border router
	_, err = exec.Command("pkill", "-SIGHUP", "-f", brID).Output()
	if err != nil {
		return common.NewBasicError("Sending SIGHUP to border routers", err)
	}
	bsProcessName := fmt.Sprintf("beacon.*%s", strings.Replace(r.cfg.ActiveAS.A.String(),
		":", "_", -1))
	_, err = exec.Command("pkill", "-SIGHUP", "-f", bsProcessName).Output()
	if err != nil {
		return common.NewBasicError("Sending SIGHUP to border routers", err)
	}
	return nil
}

// deleteInterfaceFromTopo deletes an interface from the topology file in topoPath. topoPath
// should be to the directory of the service to modify e.g. BS directory, or BR directory.
func deleteInterfaceFromTopo(brID, topoPath string, ifid common.IFIDType) (topology.RawBRIntf, error) {
	topoLock.Lock()
	topo, err := topology.LoadRawFromFile(topoPath)
	if err != nil {
		return topology.RawBRIntf{}, err
	}

	// Save a copy of the interface to revert the changes later
	iface := topo.BorderRouters[brID].Interfaces[ifid]

	// Delete the interface from the Border Router entry in the loaded topology file
	delete(topo.BorderRouters[brID].Interfaces, ifid)
	// Save new topology
	jsonData, err := json.MarshalIndent(topo, "", "  ")
	if err != nil {
		return topology.RawBRIntf{}, err
	}
	// Overwrite the topology file
	jsonFile, err := os.Create(topoPath)
	if err != nil {
		return topology.RawBRIntf{}, err
	}
	if _, err := jsonFile.Write(jsonData); err != nil {
		return topology.RawBRIntf{}, err
	}
	topoLock.Unlock()
	return *iface, nil
}

// blockPackets blocks all egress and ingress traffic to the interface with IFID r.General.IFID
func (r *Revoker) blockPackets() error {
	args := "sudo tcset --add --loss 100"

	if err := utils.BuildTcCommand(args, *r.cfg.topology, r.cfg.ActiveAS.String(),
		r.cfg.ASInfos, r.cfg.IFID); err != nil {
		return common.NewBasicError("Running tcconfig command", err)
	}

	return nil
}

// revertChanges deletes all the changes made by the revoker module to revoke an interface
func (r *Revoker) revertChanges() (err error) {
	switch r.method {
	case RevocationToken:
		break

	case BlockPackets:
		err = revertTcChanges(r.cfg)

	case ModifyTopology:
		err = r.revertTopoChanges()

	default:
		err = common.NewBasicError("Unrecognized revocation method used, nothing to change", nil,
			"method", r.method)
	}

	r.log.Info("Reverted changes", "AS", r.cfg.ActiveAS, "IFID", r.cfg.IFID, "method", r.method)

	return
}

// revertTopoChanges revert changes made to the topology file by adding
// the backed up interface in topoIfaceBackUp to the topology given by
// topoPath.
func (r *Revoker) revertTopoChanges() error {
	var err error
	// Need the Border router ID/name which belongs to that interface to
	// add it to the topology
	brID := r.cfg.topology.IFInfoMap[r.cfg.IFID].BRName
	file := filepath.Join(brID, env.DefaultTopologyPath)
	topoPath := filepath.Join(filepath.Dir(r.cfg.configDir), file)
	if err = addInterfaceToTopo(brID, topoPath, r.cfg.IFID, &r.topoIfaceBackUp); err != nil {
		return common.NewBasicError("Adding interface to border router topology file", err)
	}
	// Then add it to all BSes topology files
	for _, bs := range r.cfg.topology.BSNames {
		file := filepath.Join(bs, env.DefaultTopologyPath)
		topoPath := filepath.Join(filepath.Dir(r.cfg.configDir), file)
		if err = addInterfaceToTopo(brID, topoPath, r.cfg.IFID, &r.topoIfaceBackUp); err != nil {
			return common.NewBasicError("Adding interface to beacon server topology file", err)
		}
	}
	// Reload configuration on all of the AS's beacon services, and the modified border router
	_, err = exec.Command("pkill", "-SIGHUP", "-f", brID).Output()
	if err != nil {
		return common.NewBasicError("Sending SIGHUP to border routers", err)
	}
	bsProcessName := fmt.Sprintf("beacon.*%s", strings.Replace(r.cfg.ActiveAS.A.String(),
		":", "_", -1))
	_, err = exec.Command("pkill", "-SIGHUP", "-f", bsProcessName).Output()
	if err != nil {
		return common.NewBasicError("Sending SIGHUP to beacon servers", err)
	}

	return nil
}

// addInterfaceToTopo adds the interface iface with ID ifid to
// the border router with ID brID in the topology in topoPath.
func addInterfaceToTopo(brID, topoPath string, ifid common.IFIDType, iface *topology.RawBRIntf) error {
	topoLock.Lock()
	topo, err := topology.LoadRawFromFile(topoPath)
	if err != nil {
		return err
	}

	// Insert the old interface into the topo file the save it
	topo.BorderRouters[brID].Interfaces[ifid] = iface

	if err := utils.SaveToJSONFile(topoPath, topo); err != nil {
		return err
	}
	topoLock.Unlock()
	return nil
}

func (r *Revoker) getStop() bool {
	r.stopLock.Lock()
	v := r.stop
	r.stopLock.Unlock()
	return v
}

func (r *Revoker) setupTokenRevocation() error {
	var err error
	if err = r.initConn(); err != nil {
		return common.NewBasicError("Unable to initialize scion connection", err)
	}

	if err = r.initTrustStore(); err != nil {
		return err
	}

	r.Sign, err = r.createSigner(r.cfg.topology)
	if err != nil {
		return common.NewBasicError("Failed to create signer for revoker", err)
	}
	// interfaces and their states from the local Beacon server
	r.states, err = ifstate.GetIFStates(r.snetConn, r.cfg.LocalAddr, r.cfg.ActiveAS, r.cfg.topology)
	if err != nil {
		return common.NewBasicError("Getting IfStates", err)
	}
	return nil
}

func (r *Revoker) createSigner(topo *topology.Topo) (infra.Signer, error) {
	dir := filepath.Join(r.cfg.configDir, "keys")
	cfg, err := keyconf.Load(dir, false, false, false, false)
	if err != nil {
		return nil, common.NewBasicError("Unable to load key config", err)
	}
	ctx, cancelF := context.WithTimeout(context.Background(), time.Second)
	defer cancelF()
	meta, err := trust.CreateSignMeta(ctx, topo.ISD_AS, r.trustDB)
	if err != nil {
		return nil, common.NewBasicError("Unable to create sign meta", err)
	}
	signer, err := trust.NewBasicSigner(cfg.SignKey, meta)
	if err != nil {
		return nil, common.NewBasicError("Unable to create signer", err)
	}
	return signer, nil
}

// initTrustStore initializes the configuration by loading the keys and initializing the Trust store.
func (r *Revoker) initTrustStore() error {
	// Load the keys conf
	var err = r.loadKeyConf(r.cfg.configDir, r.cfg.topology.Core)
	if err != nil {
		return common.NewBasicError("Unable to load keys", err)
	}

	connectionKey := filepath.Join("cache", fmt.Sprintf("%s.trust.db", r.cfg.ID))
	r.trustDBConf = map[string]string{truststorage.ConnectionKey: connectionKey}
	r.trustDBConf.InitDefaults()

	if r.trustDB, err = r.trustDBConf.New(); err != nil {
		return common.NewBasicError("Unable to initialize trustDB", err)
	}

	trustConf := &trust.Config{
		// FIXME if set to false it fails, true should be for infra services only
		MustHaveLocalChain: true,
		ServiceType:        proto.ServiceType_unset,
	}

	r.store = trust.NewStore(r.trustDB, r.cfg.topology.ISD_AS, *trustConf, log.Root())
	err = r.store.LoadAuthoritativeTRC(filepath.Join(r.cfg.configDir, "certs"))
	if err != nil {
		return common.NewBasicError("Unable to load local TRC", err)
	}
	err = r.store.LoadAuthoritativeChain(filepath.Join(r.cfg.configDir, "certs"))
	if err != nil {
		return common.NewBasicError("Unable to load local Chain", err)
	}

	return nil
}

// initConn initializes scion connection and listen on the specified address.
func (r *Revoker) initConn() error {
	var err error
	if r.cfg.Dispatcher == "" {
		r.cfg.Dispatcher = reliable.DefaultDispPath
	}

	if snet.DefNetwork == nil {
		// Initialize default SCION networking context
		if err = snet.Init(r.cfg.LocalAddr.IA, r.cfg.Sciond.Path,
			reliable.NewDispatcherService(r.cfg.Dispatcher)); err != nil {
			return err
		}
	}

	connInitLock.Lock()
	r.snetConn, err = snet.ListenSCION("udp4", r.cfg.LocalAddr)
	if err != nil {
		return err
	}
	connInitLock.Unlock()

	return nil
}

// loadKeyConf loads the key configuration.
func (r *Revoker) loadKeyConf(confDir string, isCore bool) error {
	var err error
	r.keyConf, err = keyconf.Load(filepath.Join(confDir, "keys"), isCore, isCore, false, true)
	if err != nil {
		return err
	}
	return nil
}
