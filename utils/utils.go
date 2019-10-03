// Package utils has common utilities shared across different modules of the tool.
package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/docker/docker/client"
	"github.com/kaldughayem/dynlinks/conf"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/sciond"
	"github.com/scionproto/scion/go/lib/scmp"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/spath/spathmeta"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/proto"
	"gopkg.in/yaml.v2"
)

// resolveSVCAny resolves an anycast SVC address (i.e. a single instance of a local infrastructure service).
func resolveSVCAny(svc addr.HostSVC, topo *topology.Topo) (*overlay.OverlayAddr, error) {
	names, elemMap, err := getSVCNamesMap(svc, topo)
	if err != nil {
		return nil, err
	}

	name := names[rand.Intn(len(names))]
	elem := elemMap[name]
	return elem.OverlayAddr(topo.Overlay), nil
}

// getSVCNamesMap returns the slice of instance names and addresses for a given SVC address.
func getSVCNamesMap(svc addr.HostSVC, topo *topology.Topo) ([]string, map[string]topology.TopoAddr, error) {

	var names []string
	var elemMap map[string]topology.TopoAddr
	switch svc.Base() {
	case addr.SvcBS:
		names, elemMap = topo.BSNames, topo.BS
	case addr.SvcPS:
		names, elemMap = topo.PSNames, topo.PS
	case addr.SvcCS:
		names, elemMap = topo.CSNames, topo.CS
	case addr.SvcSB:
		names, elemMap = topo.SBNames, topo.SB
	case addr.SvcSIG:
		names, elemMap = topo.SIGNames, topo.SIG
	default:
		return nil, nil, common.NewBasicError("Unsupported SVC address",
			scmp.NewError(scmp.C_Routing, scmp.T_R_BadHost, nil, nil), "svc", svc)
	}
	if len(elemMap) == 0 {
		return nil, nil, common.NewBasicError("No instances found for SVC address",
			scmp.NewError(scmp.C_Routing, scmp.T_R_UnreachHost, nil, nil), "svc", svc)
	}
	return names, elemMap, nil
}

// getPath gets first path to the remote address specified
func getPath(local, remote *snet.Addr) (*spathmeta.AppPath, error) {
	pathMgr := snet.DefNetwork.PathResolver()
	pathSet := pathMgr.Query(context.Background(), local.IA, remote.IA, sciond.PathReqFlags{})

	if len(pathSet) == 0 {
		return nil, common.NewBasicError("No paths found", nil)
	}

	for _, path := range pathSet {
		return path, nil
	}

	return nil, common.NewBasicError("Paths found but couldn't return first path", nil)
}

// SetupSVCAddress gets the paths, next hop and init the offsets for the given AS.
func SetupSVCAddress(svc addr.HostSVC, localAddress *snet.Addr, remoteIA addr.IA,
	topo *topology.Topo) (*snet.Addr, error) {
	address := &snet.Addr{
		IA:   remoteIA,
		Host: &addr.AppAddr{L3: svc, L4: addr.NewL4UDPInfo(0)},
	}

	// If the destination IA is not the same as the local IA then setup the paths and next hop address
	if localAddress.IA != remoteIA {
		p, err := getPath(localAddress, address)
		if err != nil {
			return nil, common.NewBasicError("Getting paths to AS", err)
		}

		address.Path = spath.New(p.Entry.Path.FwdPath)
		// #nosec
		_ = address.Path.InitOffsets()
		address.NextHop, err = p.Entry.HostInfo.Overlay()
		if err != nil {
			return nil, common.NewBasicError("Setting paths", err)
		}
	} else {
		var err error
		address.NextHop, err = resolveSVCAny(svc, topo)
		if err != nil {
			return nil, err
		}
	}

	return address, nil
}

// SetupAddress sets the path and the next hop address to the remote address.
func SetupAddress(localAddress, remoteAddress *snet.Addr) error {
	if localAddress.IA == remoteAddress.IA {
		return nil
	}

	p, err := getPath(localAddress, remoteAddress)
	if err != nil {
		return common.NewBasicError("Getting paths to AS", err)
	}

	remoteAddress.Path = spath.New(p.Entry.Path.FwdPath)
	if err = remoteAddress.Path.InitOffsets(); err != nil {
		return common.NewBasicError("Initializing path offsets", err, "address", remoteAddress)
	}
	if remoteAddress.NextHop, err = p.Entry.HostInfo.Overlay(); err != nil {
		return common.NewBasicError("Setting address next hop ", err, "address", remoteAddress)
	}

	return nil
}

// SendPathMgmtMsg sends a PathMgmt message "u" to the service "svc" in the destination IA "dstIA".
func SendPathMgmtMsg(u proto.Cerealizable, snetConn snet.Conn, remoteAddress *snet.Addr, signer ctrl.Signer) error {

	pld, err := pack(u, signer)
	if err != nil {
		return common.NewBasicError("Packing PathMgmt payload", err)
	}

	if _, err := snetConn.WriteToSCION(pld, remoteAddress); err != nil {
		return common.NewBasicError("Writing PathMgmt payload", err, "dst", remoteAddress)
	}

	// XXX uncomment for debugging
	//log.Trace("Sent PathMgmt message", "type", common.TypeOf(u), "dst", remoteAddress, "overlayDst",
	//	remoteAddress.NextHop)

	return nil
}

// pack converts the information u into a path Management control payload.
func pack(u proto.Cerealizable, signer ctrl.Signer) (common.RawBytes, error) {
	cpld, err := ctrl.NewPathMgmtPld(u, nil, nil)
	if err != nil {
		return nil, common.NewBasicError("Packing Ctrl payload", err)
	}

	scpld, err := cpld.SignedPld(signer)
	if err != nil {
		return nil, common.NewBasicError("Generating signed Ctrl payload", err)
	}

	pld, err := scpld.PackPld()
	if err != nil {
		return nil, common.NewBasicError("Packing signed Ctrl payload", err)

	}
	return pld, nil
}

// SetASInfo gets the AS names from the specified gen path, and get the path to their configuration directories
// (where the keys and topology.json file are) and loads the topology of each AS.
func SetASInfo(genPath string, asInfos conf.ASInfos) error {
	// TODO (packages) change the assumption about the SC env var, point to /etc/scion/gen
	// Add the host AS which is also the attachment point
	iaFile := FindFile("ia", filepath.Join(os.Getenv("SC"), "gen"))
	if len(iaFile) == 0 {
		return common.NewBasicError("Finding ActiveAS file in host in dir", nil)
	}
	ia, err := ioutil.ReadFile(iaFile[0])
	if err != nil {
		return common.NewBasicError("Reading ActiveAS from file", err)
	}
	// TODO (packages) change the assumption about the SC env var, point to /etc/scion/gen
	configDirs := FindFile("keys", filepath.Join(os.Getenv("SC"), "gen"))
	if len(configDirs) == 0 {
		return common.NewBasicError("Finding keys directory in host en dir", nil)
	}
	iaStr := strings.Replace(string(ia), "_", ":", -1)

	asInfos[iaStr] = conf.ASInfo{AP: true, ConfigDir: filepath.Dir(configDirs[0])}

	// Create a new docker API cl with version 1.39 (maximum supported version)
	cl, err := client.NewClientWithOpts(client.WithVersion("1.39"))
	if err != nil {
		log.Crit("Getting docker API cl", "err", err)
		os.Exit(1)
	}

	// Add the other ASes in docker containers
	iaFiles := FindFile("ia", genPath)
	if len(iaFiles) == 0 {
		return common.NewBasicError("Finding ActiveAS files in root gen directory specified in arguments", nil)
	}
	for _, file := range iaFiles {
		// #nosec read the SCION ia files to determine which AS is this
		ia, err = ioutil.ReadFile(file)
		if err != nil {
			return common.NewBasicError("Reading IA from file", err)
		}
		iaStr := strings.Replace(string(ia), "_", ":", -1)

		// If it is the ap then do nothing to it
		if _, ok := asInfos[iaStr]; ok {
			continue
		}

		// container for this AS is not built so skip it
		if _, err := cl.ContainerInspect(context.Background(), string(ia)); err != nil {
			continue
		}

		newPath := filepath.Dir(file)
		configDirs := FindFile("keys", newPath)
		if len(configDirs) == 0 {
			return common.NewBasicError("Finding keys directory in gen directory", nil, "genPath",
				newPath)
		}

		asInfos[iaStr] = conf.ASInfo{AP: false, ConfigDir: filepath.Dir(configDirs[0])}
	}

	return nil
}

// FindFile returns all paths that contain the file name in path.
func FindFile(fileName string, path string) []string {
	var pathsFound []string
	root := path
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if filepath.Base(p) == fileName {
			pathsFound = append(pathsFound, p)
			return nil
		}
		return nil
	})

	if err != nil {
		panic(err)
	}

	return pathsFound
}

// ValidateProperties checks the given metrics and returns an error or warns the user when one or more of the validation
// checks fails.
func ValidateProperties(linkProperties *conf.LinkProperties) error {
	if err := validateRevocationParams(linkProperties); err != nil {
		return err
	}
	if err := checkRates(linkProperties); err != nil {
		return err
	}
	if err := validateDelayParams(linkProperties); err != nil {
		return err
	}
	if err := validateBandwidth(linkProperties); err != nil {
		return err
	}
	return nil
}

func validateBandwidth(linkProperties *conf.LinkProperties) error {
	// Validate the rate values
	if linkProperties.Rate != "" {
		re := regexp.MustCompile(`^\d+([MmGgTtKk]?(bps|bit/s))$`)
		rate := re.FindAllString(linkProperties.Rate, -1)
		if len(rate) != 1 {
			return common.NewBasicError("Invalid unit for bandwidth rate", nil,
				"rate", linkProperties.Rate)
		}

		// Get the number rate from the string, to make sure rate > 8bps
		re = regexp.MustCompile(`^\d+`)
		valueString := re.FindAllString(linkProperties.Rate, -1)
		// #nosec the regular expression returns numbers only
		value, _ := strconv.Atoi(valueString[0])
		if value == 0 {
			return common.NewBasicError("Invalid unit for bandwidth rate, < 8bps", nil, "rate",
				linkProperties.Rate)
		}

		if value < 8 {
			re = regexp.MustCompile("[MmGgTtKk]?(bps|bit/s)$")
			unit := re.FindAllString(linkProperties.Rate, -1)
			if unit[0] == "bps" {
				return common.NewBasicError("Rate cannot be less than 8bps", nil)
			}
		}
	}

	return nil
}

func checkRates(linkProperties *conf.LinkProperties) error {

	if ratesAreGreater(linkProperties) || ratesAreLess(linkProperties) {
		return common.NewBasicError("Loss, reordering, corruption, duplication and revocation probability rate"+
			" must all be a percentage value (0-100%)", nil)
	}

	return nil
}

func ratesAreLess(linkProperties *conf.LinkProperties) bool {
	return linkProperties.Reorder < 0 || linkProperties.Loss < 0 || linkProperties.Duplicate < 0 ||
		linkProperties.Corrupt < 0 || linkProperties.RevocationProb < 0
}

func ratesAreGreater(linkProperties *conf.LinkProperties) bool {
	return linkProperties.Reorder > 100 || linkProperties.Loss > 100 || linkProperties.Duplicate > 100 ||
		linkProperties.Corrupt > 100 || linkProperties.RevocationProb > 100
}

func validateRevocationParams(linkProperties *conf.LinkProperties) error {
	if (linkProperties.RevocationProb < 100 && !linkProperties.Revoke) ||
		(linkProperties.RevocationPeriod > 0 && !linkProperties.Revoke) {
		log.Warn("Revocation probability and/or revocation delay are set and revoke flag is false")
	}

	if err := validateRevocationMethod(linkProperties); err != nil {
		return err
	}

	return nil
}

func validateRevocationMethod(linkProperties *conf.LinkProperties) error {
	if linkProperties.RevocationMethod != "" && linkProperties.Revoke {
		re := regexp.MustCompile("^(?i)(topo|block|token)$")
		method := re.FindAllString(linkProperties.RevocationMethod, -1)
		if len(method) != 1 {
			return common.NewBasicError("Invalid revocation method", nil, "method",
				linkProperties.RevocationMethod)
		}
	} else if linkProperties.Revoke && linkProperties.RevocationMethod == "" {
		return common.NewBasicError("Revocation method not set", nil)
	}
	return nil
}

func validateDelayParams(linkProperties *conf.LinkProperties) error {
	// If reorder is set, then delay needs to be set as well to reorder packets according to the delay
	if linkProperties.Reorder > 0 && linkProperties.Delay == 0 {
		return common.NewBasicError("Delay must be set when reorder probability is set", nil)
	}
	// Delay needs to be set if dealy-distro is set
	if linkProperties.DelayDist > 0 && linkProperties.Delay == 0 {
		return common.NewBasicError("Delay must be set when distribution value is set", nil)
	}
	// Check if delay or dist in nanoseconds. tcconfig does not accept nanoseconds
	if linkProperties.Delay < time.Microsecond && linkProperties.Delay > 0 ||
		linkProperties.DelayDist < time.Microsecond && linkProperties.DelayDist > 0 {
		return common.NewBasicError("Duration values for delay and delay distribution must be >= 1us", nil)
	}

	return nil
}

// FindInterface finds the interface name on the host with the specified IP address, used to find the SCION active
// interface.
func FindInterface(targetIP string) (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, i := range interfaces {
		addresses, err := i.Addrs()
		if err != nil {
			return "", err
		}

		for _, a := range addresses {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip != nil && ip.String() == targetIP {
				return i.Name, nil
			}
		}
	}
	return "", common.NewBasicError("Interface with specified targetIP not found", nil)
}

// SetupSignals is a generic function to listen for user interrupt signal, each module calling it can add a function f
// to execute when receiving an interrupt
func SetupSignals(f func()) {
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)
	go func() {
		<-sig
		if f != nil {
			f()
		}
	}()
}

// BuildTcCommand builds and runs a tcconfig command to either delete or add rules for a specific interface "ifid"
// using tcset or tcdel args should have the base command in the beginning along with the parameters to be applied to
// all traffic incoming and outgoing to/from that interface.
func BuildTcCommand(args string, topo topology.Topo, asIA string, asInfos conf.ASInfos, ifid common.IFIDType) error {
	isAP := asInfos[asIA].AP
	// Get IP and port of incoming packets to the interface to modify from the topology for the ingress command.
	ip := topo.IFInfoMap[ifid].Local.IPv4.PublicOverlay.L3().String()
	port := topo.IFInfoMap[ifid].Local.IPv4.PublicOverlay.L4().Port()
	// Get the remote asIA overlay IP and port fot the egress command.
	remoteIP := topo.IFInfoMap[ifid].Remote.L3().String()
	remotePort := topo.IFInfoMap[ifid].Remote.L4().Port()
	remoteAS := topo.IFInfoMap[ifid].ISD_AS.String()
	ingressCmd := fmt.Sprintf("%s --network %s --port %d", args, ip, port)
	egressCmd := fmt.Sprintf("%s --network %s --port %d", args, remoteIP, remotePort)

	switch topo.IFInfoMap[ifid].LinkType {
	case proto.LinkType_parent:
		if err := handleParentLink(isAP, ip, asIA, remoteIP, remoteAS, &ingressCmd, &egressCmd, asInfos); err != nil {
			return err
		}

	case proto.LinkType_child, proto.LinkType_peer, proto.LinkType_core:
		if err := handleOtherLinkTypes(isAP, ip, asIA, remoteAS, &ingressCmd, &egressCmd); err != nil {
			return err
		}

	default:
		return common.NewBasicError("Unrecognized link type", nil, "type",
			topo.IFInfoMap[ifid].LinkType.String())
	}

	fullCmd := fmt.Sprintf("%s && %s", ingressCmd, egressCmd)
	// #nosec
	cmd := exec.Command("/bin/bash", "-c", fullCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return common.NewBasicError("Executing tc command", err, "tc output", string(out))
	}

	// XXX uncomment for debugging
	//log.Trace(fullCmd)

	return nil
}

func handleParentLink(isAP bool, ip, asIA, remoteIP, remoteAS string, ingressCmd, egressCmd *string,
	asInfos conf.ASInfos) error {
	if isAP {
		// If we are modifying the parent interface on the ap we do not have full control over the link, since it
		// is connected to a remote asIA which is a SCION attachment point, but will try to set rules for both
		// incoming and outgoing traffic on the SCION interface.

		// Get the interface on the ap which corresponds to the SCION IP address for that BR interface in the
		// topology file
		iface, err := FindInterface(ip)
		if err != nil {
			return common.NewBasicError("Finding SCION interface", err)
		}
		*ingressCmd = fmt.Sprintf("%s --direction incoming %s", *ingressCmd, iface)
		*egressCmd = fmt.Sprintf("%s --direction outgoing %s", *egressCmd, iface)

	} else { // Should not be in this case, since we only apply metrics on child links

		// The name of the container we are working on
		localContainer := strings.Replace(asIA, ":", "_", -1)
		// Check who is the parent asIA (ap or not)
		if asInfos[remoteAS].AP { //If the remote asIA is the our ap, then apply a rule to the interface
			remoteInterface, err := FindInterface(remoteIP)
			if err != nil {
				return common.NewBasicError("Finding SCION interface", err)
			}
			// Apply traffic metrics to the outgoing traffic of the remote asIA's interface.
			*ingressCmd = fmt.Sprintf("%s --direction outgoing %s", *ingressCmd, remoteInterface)
		} else {
			remoteContainer := strings.Replace(remoteAS, ":", "_", -1)
			*ingressCmd = fmt.Sprintf("%s --direction incoming --docker %s", *ingressCmd, remoteContainer)
		}
		// The direction is incoming because of a confusion in tcconfig when applying traffic rules to a docker
		// container, probably because it refers to traffic to the containers virtual interface.
		*egressCmd = fmt.Sprintf("%s --direction incoming --docker %s", *egressCmd, localContainer)
	}
	return nil
}

func handleOtherLinkTypes(isAP bool, ip, asIA, remoteAS string, ingressCmd, egressCmd *string) error {
	// Get the container name on the other side of this link because all ingress packets to this interface
	// will be coming from there so we apply the ingress rule to it.
	remoteContainer := strings.Replace(remoteAS, ":",
		"_", -1)

	if isAP {
		iface, err := FindInterface(ip)
		if err != nil {
			return common.NewBasicError("Finding SCION interface", err)
		}
		*ingressCmd = fmt.Sprintf("%s --direction incoming --docker %s", *ingressCmd, remoteContainer)
		*egressCmd = fmt.Sprintf("%s --direction outgoing %s", *egressCmd, iface)

	} else {
		localContainer := strings.Replace(asIA, ":", "_", -1)
		*ingressCmd = fmt.Sprintf("%s --direction incoming --docker %s", *ingressCmd, remoteContainer)
		*egressCmd = fmt.Sprintf("%s --direction incoming --docker %s", *egressCmd, localContainer)
	}
	return nil
}

// StringInSlice returns true if "a" is in the slice "list"
func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// SlicesEqual check if the two string slices contain the same
// elements (does not have to be in the same order)
func SlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	for _, va := range a {
		if !StringInSlice(va, b) {
			return false
		}
	}
	return true
}

// SaveToYAMLFile saves the given data structure a to a YAML file in path
func SaveToYAMLFile(path string, a interface{}) error {
	yamlData, err := yaml.Marshal(a)
	if err != nil {
		return common.NewBasicError("Marshaling data to YAML file", err)
	}
	// Check if file path already exists
	_, err = os.Stat(path)
	if err == nil {
		return common.NewBasicError("File path exists", nil, "path", path)
	}
	yamlFile, err := os.Create(path)
	if err != nil {
		return common.NewBasicError("Creating file", err)
	}
	defer yamlFile.Close()

	if _, err := yamlFile.Write(yamlData); err != nil {
		return err
	}

	if err := yamlFile.Close(); err != nil {
		return err
	}

	log.Debug("Links data written", "file", yamlFile.Name())
	return nil
}

// SaveToJSONFile saves the given data structure a to a JSON file in path
func SaveToJSONFile(path string, a interface{}) error {
	// Save new topology
	jsonData, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	// Overwrite the existing topology file
	jsonFile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer jsonFile.Close()
	if _, err := jsonFile.Write(jsonData); err != nil {
		return err
	}
	return nil
}

// LoadYAML loads the specified YAML file into the a interface
func LoadYAML(file string, a interface{}) error {
	// #nosec
	yamlFile, err := os.Open(file)
	if err != nil {
		return common.NewBasicError("Opening YAML file", err)
	}

	byteValue, err := ioutil.ReadAll(yamlFile)
	if err != nil {
		return common.NewBasicError("Reading YAML file", err)
	}

	if err := yaml.Unmarshal(byteValue, a); err != nil {
		return common.NewBasicError("Loading dat from YAML file to structure", err)
	}
	return nil
}

// commandExists Checks if command exists on the host machine
func CommandExists(name string) bool {
	// #nosec
	cmd := exec.Command("/bin/sh", "-c", "command -v "+name)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// CheckAndCreateDir checks if the directory name "dir" exists and creates it if it doesn't with permissions 0750
func CheckAndCreateDir(dir string) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.Mkdir(dir, 0750); err != nil {
			return common.NewBasicError("Creating directory", err)
		}
	}
	return nil
}

// OutputProperties writes the current topology links' structure and empty properties to a file
func OutputProperties(fileName, genDirPath string) error {
	asInfos := make(conf.ASInfos)
	if err := SetASInfo(genDirPath, asInfos); err != nil {
		return common.NewBasicError("Loading AS infos from the gen directory", err)
	}

	links := make(conf.Links)
	if err := conf.BuildLinks(links, asInfos); err != nil {
		return common.NewBasicError("Building links failed", err)
	}

	if err := SaveToYAMLFile(fileName, &links); err != nil {
		return common.NewBasicError("Saving file", err)
	}

	return nil
}
