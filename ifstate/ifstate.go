// Package ifstate holds the interfaces structure and all its supporting functions.
// At first run it should get all the interfaces states (IfStates) from the
// beacon server to initialize all the States.
package ifstate

import (
	"github.com/kaldughayem/dynlinks/utils"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
	"time"
)

const (
	maxBufSize = 64 * 1024
)

// IfStates is a map of interface IDs to interface States.
type IfStates map[common.IFIDType]*IfState

// IfState holds the state of an interface and its revocation info if it exists
type IfState struct {
	// IfID is the ID of the interface
	IfID common.IFIDType
	// Active true if interface is active
	Active bool
	// Revoke is a flag which is set when an interface is to be revoked
	Revoked bool
	// SRevInfo is the signed revocation info of the interface
	SRevInfo *path_mgmt.SignedRevInfo
	// RawSRev the raw revocation info of the interface
	RawSRev common.RawBytes
}

// Revoke checks the revoked flag of the interface, and sets the revocation info for that info and sets it state to
// inactive.
func (i *IfState) Revoke(rev *path_mgmt.SignedRevInfo) error {
	if !i.Revoked {
		return common.NewBasicError("Cannot revoke interface, revoke flag is not set", nil)
	}
	i.Active = false
	i.RawSRev = rev.Blob
	i.SRevInfo = rev
	return nil
}

// newIfState returns a new interface state based on the given parameters
func newIfState(ifID common.IFIDType, active bool, srev *path_mgmt.SignedRevInfo,
	rawSRev common.RawBytes) *IfState {
	i := &IfState{
		IfID:     ifID,
		Active:   active,
		SRevInfo: srev,
		RawSRev:  rawSRev,
		Revoked:  false,
	}
	return i
}

// process processes interface State updates from the beacon server.
func process(ifStates *path_mgmt.IFStateInfos) IfStates {
	states := make(IfStates)
	for _, info := range ifStates.Infos {
		var rawSRev common.RawBytes
		ifid := common.IFIDType(info.IfID)
		if info.SRevInfo != nil {
			var err error
			rawSRev, err = proto.PackRoot(info.SRevInfo)
			if err != nil {
				log.Error("Unable to pack SRevInfo", "err", err)
				return nil
			}
		}
		stateInfo := newIfState(ifid, info.Active, info.SRevInfo, rawSRev)
		_, ok := states[ifid]
		if !ok {
			states[ifid] = stateInfo
			continue
		}
		states[ifid] = stateInfo
	}
	return states
}

// BuildIFStatesUpdate builds an IFStateInfos update message for the revoked interfaces only
// based on the passed interface states.
func BuildIFStatesUpdate(states IfStates, topo *topology.Topo) (*path_mgmt.IFStateInfos, error) {
	stateInfos := &path_mgmt.IFStateInfos{}
	for ifid := range topo.IFInfoMap {
		s, ok := states[ifid]
		if !ok {
			return nil, common.NewBasicError("Interface not found in IFState map", nil)
		}
		if !s.Revoked {
			continue
		}
		newInfo := &path_mgmt.IFStateInfo{
			IfID:     s.IfID,
			Active:   s.Active,
			SRevInfo: s.SRevInfo,
		}
		stateInfos.Infos = append(stateInfos.Infos, newInfo)
	}
	return stateInfos, nil
}

// GetIFStates is  the main function in the module, generates and sends IfState requests to the beacon server, then
// processes the response to update the local IfState information.
func GetIFStates(conn snet.Conn, LocalAddress *snet.Addr, dstAS addr.IA, topo *topology.Topo) (IfStates, error) {
	b := make(common.RawBytes, maxBufSize)

	if err := sendIFStateReq(conn, LocalAddress, dstAS, topo); err != nil {
		return nil, common.NewBasicError("Sending IfState request", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return nil, common.NewBasicError("Setting deadline for read IfState req reply", err)
	}

	pktLen, _, err := conn.ReadFromSCION(b)
	if err != nil {
		return nil, common.NewBasicError("Reading IfState reply", err)
	}
	states, err := processCtrlFromRaw(b[:pktLen])
	if err != nil {
		return nil, common.NewBasicError("Processing ctrl pld from IfState reply", err)
	}

	if states == nil {
		return nil, common.NewBasicError("Got empty states from the Beacon Server", err)
	}

	return states, nil
}

// sendIFStateReq generates an Interface State request packet to the beacon service in the currently active AS .
func sendIFStateReq(snetConn snet.Conn, LocalAddress *snet.Addr, dstAS addr.IA, topo *topology.Topo) error {
	dst, err := utils.SetupSVCAddress(addr.SvcBS, LocalAddress, dstAS, topo)
	if err != nil {
		return common.NewBasicError("Setting up address", err)
	}
	err = utils.SendPathMgmtMsg(&path_mgmt.IFStateReq{}, snetConn, dst, infra.NullSigner)
	if err != nil {
		return common.NewBasicError("Sending IFStateReq", err)
	}
	return nil
}

// processCtrlFromRaw processes the path management scion ctrl payload from raw bytes, returns
// an error if the payload is not of type path_mgmt.Pld
func processCtrlFromRaw(b common.RawBytes) (IfStates, error) {
	scPld, err := ctrl.NewSignedPldFromRaw(b)
	if err != nil {
		return nil, common.NewBasicError("Parsing signed ctrl pld", nil, "err", err)
	}

	cPld, err := scPld.UnsafePld()
	if err != nil {
		return nil, common.NewBasicError("Getting ctrl pld", nil, "err", err)
	}
	// Determine the type of SCION control payload.
	u, err := cPld.Union()
	if err != nil {
		return nil, err
	}
	switch pld := u.(type) {
	case *path_mgmt.Pld:
		return processPathMgmtSelf(pld)
	}
	return nil, common.NewBasicError("Unsupported control payload", nil,
		"pld", cPld.String())
}

// processPathMgmtSelf handles Path Management SCION control messages.
func processPathMgmtSelf(p *path_mgmt.Pld) (IfStates, error) {
	u, err := p.Union()
	if err != nil {
		return nil, err
	}
	switch pld := u.(type) {
	case *path_mgmt.IFStateInfos:
		return process(pld), nil
	default:
		return nil, common.NewBasicError("Unsupported PathMgmt payload", nil,
			"type", common.TypeOf(pld))
	}
}
