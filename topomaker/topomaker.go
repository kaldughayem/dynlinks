// Package topomaker is in charge of parsing the topology configuration file, creating new docker containers and
// networks if needed, and editing the topology.json files to reflect the parameters in the topology configuration file.
package topomaker

import (
	"bufio"
	"context"
	rand2 "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/fileutils"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/kaldughayem/dynlinks/conf"
	"github.com/kaldughayem/dynlinks/utils"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/overlay"
	"github.com/scionproto/scion/go/lib/topology"
)

const (
	defaultBandwidth       = 1000
	defaultNetworkName     = "scion-docker-net"
	temporaryBinsDirectory = "/tmp/dynlinks/"
)

// Run builds the new topology structures, save them to files, and starts the new docker topology
func Run(topoFile, outputLinks string, installSCIONApps bool) {
	if topoFile == "" {
		log.Crit("Topology configuration YAML file not specified")
		os.Exit(1)
	}
	topoConfig := new(conf.TopoConfig)
	//	Load yaml file
	if err := utils.LoadYAML(topoFile, topoConfig); err != nil {
		log.Crit("Loading topology config file", "name", topoFile, "err", err)
		os.Exit(1)
	}

	// Create a new docker API cl with version 1.39 (maximum supported version)
	cl, err := client.NewClientWithOpts(client.WithVersion("1.39"))
	if err != nil {
		log.Crit("Getting docker API client", "err", err)
		os.Exit(1)
	}

	// Make checks
	if err := check(topoConfig, cl); err != nil {
		log.Crit("Making basic checks", "err", err)
		os.Exit(1)
	}
	// Set the gen directories
	if err := setGenDirs(topoConfig.GenDir, topoConfig.ASes); err != nil {
		log.Crit("Loading gen directories", "err", err)
		os.Exit(1)
	}

	// make containers
	if err := handleContainers(cl, topoConfig); err != nil {
		log.Crit("Handling containers", "err", err)
		os.Exit(1)
	}

	// create and/or attach containers to the network then set their IP addresses in the topoConfig struct
	if err := handleNetwork(cl, topoConfig.Subnet, topoConfig.NetworkName, topoConfig.MTU,
		topoConfig.ASes); err != nil {
		log.Crit("Handling network", "err", err)
		os.Exit(1)
	}

	// install scion apps
	if installSCIONApps {
		installApps(cl, topoConfig.ASes)
	}

	log.Info("Generating new topology files...")
	// generate new topology.json files
	if err := generateTopologyFiles(topoConfig); err != nil {
		log.Crit("Generating new topology files", "err", err)
		os.Exit(1)
	}

	log.Info("checking and generating TLS certificates...")
	if err := generateCerts(topoConfig); err != nil {
		log.Crit("Unable to generate certificates for containers in 'gen-certs' dir", "err", err)
	}
	// restart all SCION services
	startNewTopology(cl, topoConfig.ASes)

	log.Info("New topology started successfully")

	if outputLinks != "" {
		log.Info("Generating empty links' properties file...")
		if err := utils.OutputProperties(outputLinks, topoConfig.GenDir); err != nil {
			log.Error("Generating empty links' properties file", "err", err)
		}
	}

	os.Exit(0)
}

// generateCerts generates the certificates in gen-certs if they do not exist. The beacon server,
// path server, and scion daemon won't start if the certs are not there.
func generateCerts(config *conf.TopoConfig) error {
	for as, info := range config.ASes {
		// Check if the certificates exist
		if _, err := os.Stat(filepath.Join(info.Info.ConfigDir, "gen-certs", "tls.key")); err == nil {
			if _, err := os.Stat(filepath.Join(info.Info.ConfigDir, "gen-certs", "tls.pem")); err == nil {
				continue
			}
		}
		if err := utils.CheckAndCreateDir(filepath.Join(info.Info.ConfigDir, "gen-certs")); err != nil {
			return err
		}

		// populate the certificate data
		template := &x509.Certificate{
			IsCA:                  true,
			BasicConstraintsValid: true,
			SubjectKeyId:          []byte{1, 2, 3},
			SerialNumber:          big.NewInt(1234),
			Subject: pkix.Name{
				CommonName: "scion_def_srv",
			},
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(10, 0, 0),
			// see http://golang.org/pkg/crypto/x509/#KeyUsage
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		}

		// generate private key
		privatekey, err := rsa.GenerateKey(rand2.Reader, 2048)
		if err != nil {
			return err
		}
		publickey := &privatekey.PublicKey

		// create a self-signed certificate. template = parent
		var parent = template
		cert, err := x509.CreateCertificate(rand2.Reader, template, parent, publickey, privatekey)
		if err != nil {
			return err
		}

		path := filepath.Join(info.Info.ConfigDir, "gen-certs")
		// save private key
		pemfile, _ := os.Create(filepath.Join(path, "tls.key"))
		var pemkey = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privatekey)}
		if err := pem.Encode(pemfile, pemkey); err != nil {
			return err
		}
		pemfile.Close()
		log.Debug("Private key generated and saved to tls.key", "AS", as)

		// save the certificate.
		pemfile, _ = os.Create(filepath.Join(path, "tls.pem"))
		var pemcert = &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert}
		if err := pem.Encode(pemfile, pemcert); err != nil {
			return err
		}
		pemfile.Close()
		log.Debug("Certificate created and saved to tls.pem", "AS", as)

	}
	return nil
}

// startNewTopology reloads the supervisor, builds the binaries on one of the containers,
// copies the binaries to other containers, and restarts SCION on all containers and the host machine
func startNewTopology(cl *client.Client, asMap conf.ASMap) {
	log.Info("Restarting the SCION services...")
	// restart SCION services on the local host
	cmd := exec.Command("./scion.sh", "stop")
	cmd.Dir = os.Getenv("SC")
	if err := cmd.Run(); err != nil {
		log.Error("Stopping SCION on host", "err", err)
	}
	cmd = exec.Command("supervisor/supervisor.sh", "reload")
	cmd.Dir = os.Getenv("SC")
	if err := cmd.Run(); err != nil {
		log.Error("Reloading supervisor on host", "err", err)
	}
	cmd = exec.Command("./scion.sh", "start", "nobuild")
	cmd.Dir = os.Getenv("SC")
	if err := cmd.Run(); err != nil {
		log.Error("Starting SCION on host", "err", err)
	}

	for as, info := range asMap {
		if info.Info.AP {
			continue
		}
		containerName := strings.Replace(as, ":", "_", -1)

		output, err := runCommandInContainer(cl, containerName, nil, types.ExecConfig{
			User:         "scion",
			AttachStderr: true,
			AttachStdout: true,
			Cmd:          []string{"./scion.sh", "stop"},
		})
		if err != nil {
			log.Error("Stopping SCION", "container", containerName, "err", err, "output", output)
		} else {
			log.Debug("Stopped SCION", "container", containerName)
		}

		// reload supervisord
		output, err = runCommandInContainer(cl, containerName, nil, types.ExecConfig{
			User:         "scion",
			AttachStderr: true,
			AttachStdout: true,
			Cmd:          []string{"supervisor/supervisor.sh", " reload"},
		})
		if err != nil {
			log.Error("Reloading supervisor", "container", containerName, "err", err, "output", output)
		} else {
			log.Debug("Reloaded supervisor", "container", containerName)
		}

		var cmd []string
		var out io.Writer
		// check if scion is built
		if scionBuilt(cl, containerName) {
			log.Debug("Found SCION built in container", "container", containerName)
			cmd = []string{"./scion.sh", "start", "nobuild"}
		} else {
			log.Debug("SCION not built in container", "container", containerName)
			if _, err := os.Stat(temporaryBinsDirectory); os.IsNotExist(err) {
				log.Trace("Building binaries")
				cmd = []string{"./scion.sh", "start"}
				out = os.Stdout
			} else {
				log.Trace("Putting built binaries in container", "container", containerName)
				dstPath := "/home/scion/go/src/github.com/scionproto/scion/"
				if err := putBinaries(cl, containerName, temporaryBinsDirectory, dstPath); err != nil {
					log.Error("Copying binaries to container", "container", containerName, "err", err)
				}
				cmd = []string{"./scion.sh", "start", "nobuild"}
				out = nil
			}
		}
		log.Debug("Starting SCION...", "container", containerName)
		_, err = runCommandInContainer(cl, containerName, out, types.ExecConfig{
			User:         "scion",
			AttachStderr: true,
			AttachStdout: true,
			Cmd:          cmd,
		})
		if err != nil {
			log.Error("Starting SCION in container", "err", err)
		}

		// Get the binaries from the container if we don't have them
		if _, err := os.Stat(temporaryBinsDirectory); os.IsNotExist(err) {
			log.Trace("Getting built binaries from container", "container", containerName)
			if err := utils.CheckAndCreateDir(temporaryBinsDirectory); err != nil {
				log.Error("Creating temporary directory", "name", temporaryBinsDirectory)
			}
			srcPath := "/home/scion/go/src/github.com/scionproto/scion/bin/"
			if err := getBinaries(cl, containerName, srcPath, temporaryBinsDirectory); err != nil {
				log.Error("Getting binaries from container", "container", containerName, "err", err)
			}
		}
	}

	if err := os.RemoveAll(temporaryBinsDirectory); err != nil {
		log.Error("Removing the temporary bins directory", "err", err)
	}

}

// putBinaries copies the binaries from srcPath to the container cnt
func putBinaries(cl *client.Client, cnt, srcPath, dstPath string) error {
	reader, err := archive.Tar(srcPath, archive.Uncompressed)
	if err != nil {
		return common.NewBasicError("Compressing binaries", err)
	}

	if err := cl.CopyToContainer(context.Background(), cnt, dstPath, reader, types.CopyToContainerOptions{
		AllowOverwriteDirWithFile: true,
		CopyUIDGID:                false,
	}); err != nil {
		return err
	}

	return nil
}

// getBinaries copies the SCION binaries from the container cnt to dstPath on the host machine
func getBinaries(cl *client.Client, cnt, srcPath, dstPath string) error {
	reader, _, err := cl.CopyFromContainer(context.Background(), cnt, srcPath)
	if err != nil {
		return err
	}

	if err := archive.Untar(reader, dstPath, &archive.TarOptions{IncludeSourceDir: false}); err != nil {
		return common.NewBasicError("Unpacking the binaries from the container", err)
	}
	return nil
}

// scionBuilt checks if SCION is built inside a container
func scionBuilt(cl *client.Client, containerName string) bool {
	execConfig := types.ExecConfig{
		User:         "scion",
		AttachStderr: true,
		AttachStdout: true,
		Detach:       false,
		Env:          []string{"SC=/home/scion/go/src/github.com/scionproto/scion"},
		Cmd:          []string{"ls", "bin"},
	}
	output, err := runCommandInContainer(cl, containerName, nil, execConfig)
	if err != nil {
		log.Error("Running ls command in container to check if SCION is built", "err", err,
			"output", output)
		return false
	}

	if len(output) < 25 {
		return false
	}

	return true
}

//generateTopologyFiles generates the new topology files based on the topology configuration passed
func generateTopologyFiles(topoConfig *conf.TopoConfig) error {
	if err := loadTopologies(topoConfig.ASes); err != nil {
		return err
	}

	// Add the new interfaces
	for _, link := range topoConfig.Links {
		if err := addInterface(link, topoConfig.ASes, topoConfig.MTU); err != nil {
			return err
		}
	}

	// Save new topologies
	if err := saveTopologyFiles(topoConfig.ASes); err != nil {
		return common.NewBasicError("Saving topology files", err)
	}

	log.Info("Added interfaces to topology files")

	return nil
}

// saveTopologyFiles saves the topologies in asMap passed to topology.json files
func saveTopologyFiles(asMap conf.ASMap) error {
	outputDir := "new_topology_files"
	log.Warn("Need to overwrite old topology files to continue execution")
	if promptUser("Overwrite old topology files? (even the ones in host machine's AS)") {
		for _, info := range asMap {
			if err := replaceTopologyFiles(info.Topo, filepath.Join(info.Info.ConfigDir, "gen")); err != nil {
				return err
			}
		}
	} else {
		// Create the root dir to save the new files to
		if err := utils.CheckAndCreateDir(outputDir); err != nil {
			return err
		}
		// create a dir for each AS and save the topology files there
		for as, info := range asMap {
			out := filepath.Join(outputDir, strings.Replace(as, ":", "_", -1))
			if err := utils.CheckAndCreateDir(out); err != nil {
				return err
			}

			if err := utils.SaveToJSONFile(filepath.Join(out, env.DefaultTopologyPath), info.Topo); err != nil {
				return err
			}
		}
		log.Info("Saved new topology files", "dir", outputDir)
		os.Exit(0)
	}
	return nil
}

// replaceTopologyFiles replaces the all topology.json files in rootDir with topo
func replaceTopologyFiles(topo *topology.RawTopo, rootDir string) error {
	return filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() { // process log files based ion their parent dir name
			if info.Name() == env.DefaultTopologyPath {
				if err := utils.SaveToJSONFile(path, topo); err != nil {
					return err
				}
				log.Trace("Replaced topology file", "dst", path)
			}
		}
		return nil
	})
}

// addInterface adds an interface to the topology structure of both ASes on the link passed
func addInterface(link conf.TopoLink, asMap conf.ASMap, networkMTUStr string) error {
	// check if the network's MTU is set
	if networkMTUStr == "" {
		networkMTUStr = "1500"
	}

	if _, ok := asMap[link.B]; !ok {
		return common.NewBasicError("AS in links not defined in passed ASes map", nil, "AS", link.B)
	}
	if _, ok := asMap[link.A]; !ok {
		return common.NewBasicError("AS in links not defined in passed ASes map", nil, "AS", link.A)
	}

	// Check if AS MTU was set
	if asMap[link.B].MTU > 0 {
		asMap[link.B].Topo.MTU = asMap[link.B].MTU
	}
	if asMap[link.A].MTU > 0 {
		asMap[link.A].Topo.MTU = asMap[link.A].MTU
	}

	networkMTU, err := strconv.Atoi(networkMTUStr)
	if err != nil {
		return common.NewBasicError("Parsing network's MTU", err)
	}

	// Modify the first border router found
	localBR := getFirstBR(asMap[link.A].Topo.BorderRouters)
	// Choose a random port number between 50000-51000
	localPort := rand.Intn(1000) + 50000
	// check if its used then choose another one
	for portUsed(localPort, localBR) {
		localPort = rand.Intn(1000) + 50000
	}

	// Do the same for the remote port
	remoteBR := getFirstBR(asMap[link.B].Topo.BorderRouters)
	remotePort := rand.Intn(1000) + 50000
	for portUsed(remotePort, remoteBR) {
		remotePort = rand.Intn(1000) + 50000
	}

	if err := setInterfaceProperties(&link, networkMTU); err != nil {
		return err
	}

	newLocalIface := &topology.RawBRIntf{
		Overlay: link.Overlay,
		PublicOverlay: &topology.RawAddrOverlay{
			Addr:        asMap[link.A].IP,
			OverlayPort: localPort,
		},
		BindOverlay: link.BindOverlay,
		RemoteOverlay: &topology.RawAddrOverlay{
			Addr:        asMap[link.B].IP,
			OverlayPort: remotePort,
		},
		Bandwidth: link.Bandwidth,
		ISD_AS:    link.B,
		LinkTo:    link.LinkAtoB,
		MTU:       link.MTU,
	}
	checkInterface(asMap[link.A], localBR, newLocalIface)
	log.Trace("Added interface to topology", "AS", link.A, "IFID", asMap[link.A].IfID)

	newRemoteInterface := &topology.RawBRIntf{
		Overlay: link.Overlay,
		PublicOverlay: &topology.RawAddrOverlay{
			Addr:        asMap[link.B].IP,
			OverlayPort: remotePort,
		},
		BindOverlay: link.BindOverlay,
		RemoteOverlay: &topology.RawAddrOverlay{
			Addr:        asMap[link.A].IP,
			OverlayPort: localPort,
		},
		Bandwidth: link.Bandwidth,
		ISD_AS:    link.A,
		MTU:       link.MTU,
	}

	switch link.LinkAtoB {
	case topology.ParentLinkName:
		newRemoteInterface.LinkTo = topology.ParentLinkName
	case topology.ChildLinkName:
		newRemoteInterface.LinkTo = topology.ParentLinkName
	case topology.PeerLinkName, topology.CoreLinkName:
		newRemoteInterface.LinkTo = link.LinkAtoB
	default:
		return common.NewBasicError("Unrecognized link type", nil)
	}
	checkInterface(asMap[link.B], remoteBR, newRemoteInterface)
	log.Trace("Added interface to topology", "AS", link.B, "IFID", asMap[link.B].IfID)
	return nil
}

// setInterfaceProperties checks an interface and sets its bandwidth, MTU, and overlay type.
func setInterfaceProperties(link *conf.TopoLink, networkMTU int) error {
	if link.MTU == 0 {
		link.MTU = networkMTU - 42
	}

	if link.MTU > networkMTU-42 {
		if promptUser("link MTU set higher than network MTU (minus Ethernet, IPv4, and UDP headers is " +
			" 42 Bytes), set to max virtual interface MTU " + string(networkMTU-42) + "?") {
			log.Info("Setting MTU to max MTU ", networkMTU-42)
			link.MTU = networkMTU - 42
		}
		log.Info("Using Specified MTU")
	}
	if link.Bandwidth == 0 {
		link.Bandwidth = defaultBandwidth
	}
	if link.Overlay == "" {
		link.Overlay = overlay.UDPIPv4Name
	}
	if !utils.StringInSlice(link.LinkAtoB, []string{topology.CoreLinkName, topology.ParentLinkName,
		topology.ChildLinkName, topology.PeerLinkName}) {
		return common.NewBasicError("Unrecognized link type", nil)
	}

	return nil
}

// checkInterface checks if the interface exist already if we are working on the host machines AS and prompts the user
// to keep or overwrite the existing interface.
func checkInterface(asInfo *conf.AS, brInfo *topology.RawBRInfo, intf *topology.RawBRIntf) {
	if asInfo.Info.AP {
		//	If the interface exists, then prompt the user to overwrite it
		for {
			if interfaceExists(asInfo.IfID, brInfo.Interfaces) {
				log.Warn("Interface already exists in AP's topology", "IFID", asInfo.IfID)
				if promptUser("Overwrite old interface?") {
					break
				} else {
					asInfo.IfID++
				}
			} else {
				break
			}
		}
	} else if asInfo.IfID == 1 {
		// delete all other interface entries in non AP topology files
		// if we are adding the first interface.
		localBR := getFirstBR(asInfo.Topo.BorderRouters)
		for id := range localBR.Interfaces {
			delete(localBR.Interfaces, id)
		}
	}

	brInfo.Interfaces[asInfo.IfID] = intf
	asInfo.IfID++
}

func interfaceExists(newIfID common.IFIDType, interfaces map[common.IFIDType]*topology.RawBRIntf) bool {
	for ifid := range interfaces {
		if ifid == newIfID {
			return true
		}
	}
	return false
}

func getFirstBR(brMap map[string]*topology.RawBRInfo) *topology.RawBRInfo {
	for _, elem := range brMap {
		return elem
	}
	return nil
}

func portUsed(port int, br *topology.RawBRInfo) bool {
	for _, iface := range br.Interfaces {
		if port == iface.PublicOverlay.OverlayPort {
			return true
		}
	}
	return false
}

// loadTopologies loads the topology files for each AS from its config dir into a RawTopo structure.
func loadTopologies(asMap conf.ASMap) error {
	var err error
	for _, info := range asMap {
		var topologyFiles []string
		if info.Info.AP {
			// get correct topology file and load it
			topologyFiles = utils.FindFile(env.DefaultTopologyPath, filepath.Join(info.Info.ConfigDir, "gen"))

		} else {
			// get correct topology file and load it
			topologyFiles = utils.FindFile(env.DefaultTopologyPath, info.Info.ConfigDir)
		}

		if len(topologyFiles) == 0 {
			return common.NewBasicError("Couldn't find topology files", nil,
				"root dir", info.Info.ConfigDir)
		}

		info.Topo, err = topology.LoadRawFromFile(topologyFiles[0])
		if err != nil {
			return common.NewBasicError("Loading topology file", err)
		}

		if info.Info.AP {
			//Do not modify the parent connection if we are working on the AP AS (the AS on the host machine)
			info.IfID = 2
		} else {
			info.IfID = 1
		}

	}
	return nil
}

// installApps installs SCION apps on all the simultaneously containers
func installApps(cl *client.Client, asMap conf.ASMap) {
	for as, info := range asMap {
		if info.Info.AP {
			continue
		}
		name := strings.Replace(as, ":", "_", -1)
		if appInstalled(cl, name) {
			log.Debug("Found SCION applications built, getting apps binaries", "container", name)
			if _, err := os.Stat(temporaryBinsDirectory); os.IsNotExist(err) {
				if err := utils.CheckAndCreateDir(temporaryBinsDirectory); err != nil {
					log.Error("Creating temporary directory", "name", temporaryBinsDirectory)
				}
				srcPath := "/home/scion/go/bin/"
				if err := getBinaries(cl, name, srcPath, temporaryBinsDirectory); err != nil {
					log.Error("Getting apps binaries", "err", err)
				}
			}
			continue
		}
		if _, err := os.Stat(temporaryBinsDirectory); os.IsNotExist(err) {
			log.Debug("Installing SCION applications in container, this might take a while...",
				"container name", name)
			installAppInContainer(cl, name, info.Info.ConfigDir)
			if err := utils.CheckAndCreateDir(temporaryBinsDirectory); err != nil {
				log.Error("Creating temporary directory", "name", temporaryBinsDirectory)
			}
			srcPath := "/home/scion/go/bin/"
			if err := getBinaries(cl, name, srcPath, temporaryBinsDirectory); err != nil {
				log.Error("Getting apps binaries", "err", err)
			}
		} else if err == nil {
			log.Debug("Putting SCION apps binaries in container...",
				"container name", name)
			dstPath := "/home/scion/go/bin/"
			if err := putBinaries(cl, name, temporaryBinsDirectory, dstPath); err != nil {
				log.Error("Putting built binaries in container", "container", name)
			}
		}
	}

}

// appInstalled checks if bwtester is installed on the container
func appInstalled(cl *client.Client, containerName string) bool {
	execConfig := types.ExecConfig{
		User:         "scion",
		AttachStderr: true,
		AttachStdout: true,
		Detach:       false,
		Env:          []string{"SC=/home/scion/go/src/github.com/scionproto/scion"},
		Cmd:          []string{"ls", "/home/scion/go/bin"},
	}
	output, err := runCommandInContainer(cl, containerName, nil, execConfig)
	if err != nil {
		log.Error("Running ls command in container to check if SCION is built", "err", err,
			"output", output)
		return false
	}

	if strings.Contains(output, "bwtestclient") && strings.Contains(output, "bwtestserver") {
		return true
	}

	return false
}

// installAppInContainer installs SCION apps inside the container
func installAppInContainer(cl *client.Client, containerName, dir string) {
	defer func() {
		log.Info("Finished installing apps", "container", containerName)
		//wg.Done()
	}()
	// move the script to the mounted directory
	script := "install_apps.sh"
	dst := filepath.Join(dir, "gen", script)
	if _, err := fileutils.CopyFile(script, dst); err != nil {
		log.Error("Copying script to container mounted dir", "err", err)
	}

	if _, err := runCommandInContainer(cl, containerName, os.Stdout, types.ExecConfig{
		User:         "root",
		AttachStderr: true,
		AttachStdout: true,
		Detach:       false,
		Env:          []string{"SC=/home/scion/go/src/github.com/scionproto/scion"},
		Cmd:          []string{"sh", "gen/install_apps.sh"},
	}); err != nil {
		log.Error("Running command in container", "err", err)
	}

}

// handleNetwork checks if the user specified another network to use other than the docker
// default network, creates a new network if needed, attaches containers to the network,
// and finally gets the IP addresses for each of the containers and the host machine and
// sets it in the passed asMap.
func handleNetwork(cl *client.Client, subnetStr, newNetworkName, mtu string, asMap conf.ASMap) error {
	_, subnet, err := net.ParseCIDR(subnetStr)
	if err != nil {
		return common.NewBasicError("Parsing subnet", err)
	}

	dockerDefaultIP, err := dockerDefaultNetwork()
	if err != nil {
		return err
	}

	if subnet.Contains(dockerDefaultIP) {
		log.Info("Using docker default network")
		_, err = cl.NetworkInspect(context.Background(), "bridge", types.NetworkInspectOptions{})
		if err != nil {
			return err
		}
		newNetworkName = "bridge"
	} else {
		log.Info("Creating new docker network")
		if newNetworkName == "" {
			log.Debug("New network name not specified, using \"scion-docker-net\" name for the " +
				"new docker network")
			newNetworkName = defaultNetworkName
		}
		err = createNetwork(cl, newNetworkName, mtu, subnet)
		if err != nil {
			return common.NewBasicError("Creating new docker network", err)
		}
	}

	// attach containers to network
	for asID, info := range asMap {
		if info.Info.AP {
			// set the IP of the AP as the gateway address for the docker network
			ip := subnet.IP.To4()
			ip[3] |= subnet.Mask[3] + 1
			info.IP = ip.String()
			continue
		}

		containerName := strings.Replace(asID, ":", "_", -1)
		// connect the containers if we are not using the default network
		if !subnet.Contains(dockerDefaultIP) {
			if err := cl.NetworkConnect(context.Background(), newNetworkName, containerName,
				&network.EndpointSettings{
					NetworkID: newNetworkName,
					IPAddress: info.IP,
				}); err != nil {
				log.Error("Connecting container to network", "err", err)
				if !promptUser("Do you want to continue the setup?") {
					return err
				}
			}
		}

		// Get the IP address of the container
		cnt, err := cl.ContainerInspect(context.Background(), containerName)
		if err != nil {
			//	This should never happen
			return common.NewBasicError("Could not retrieve container", err)
		}
		info.IP = cnt.NetworkSettings.Networks[newNetworkName].IPAddress
	}
	return nil
}

// createNetwork checks if the docker network to be created exists, and prompts the user to connect
// containers to it if it does.
// Creates a new docker network if it doesn't exist with the specified name, mtu, and subnet.
func createNetwork(cl *client.Client, networkName, mtu string, subnet *net.IPNet) error {
	// Check if the network with the same name exists and ask user to connect to it
	if _, err := cl.NetworkInspect(context.Background(), networkName, types.NetworkInspectOptions{}); err == nil {
		if !promptUser(fmt.Sprintf("Network \"%s\" exists, do you want to connect the containers"+
			" to this network?",
			networkName)) {
			return common.NewBasicError("Network with the same name exists, please specify a "+
				"different name", nil)
		}
		return nil
	}
	// create a new network
	gateway := subnet.IP.To4()
	gateway[3]++

	ipamConfig := network.IPAMConfig{
		Subnet:  subnet.String(),
		Gateway: gateway.String(),
	}

	if mtu == "" {
		mtu = "1500"
	}
	_, err := cl.NetworkCreate(context.Background(), networkName,
		types.NetworkCreate{
			CheckDuplicate: true,
			IPAM:           &network.IPAM{Config: []network.IPAMConfig{ipamConfig}},
			Options:        map[string]string{"com.docker.network.driver.mtu": mtu},
		})
	if err != nil {
		return err
	}

	return nil
}

// handleContainers handles the creation or resuming of containers (if they exist) in order to start
// SCION services on the container.
func handleContainers(cl *client.Client, topoConfig *conf.TopoConfig) error {
	for asID, info := range topoConfig.ASes {
		if info.Info.AP {
			continue
		}

		// set container name
		containerName := strings.Replace(asID, ":", "_", -1)

		// check if container exists
		container, err := cl.ContainerInspect(context.Background(), containerName)
		// container found
		if err == nil {
			if utils.StringInSlice(container.State.Status, []string{"exited", "paused", "running"}) {
				if err := startContainer(container, cl); err != nil {
					log.Error("Starting stopped container", "err", err)
					if !promptUser(fmt.Sprintf("Recreate container %s? ", containerName)) {
						return common.NewBasicError("Couldn't start container", err)
					}
				} else {
					continue
				}
			}
		}
		// create or re-create the container if it doesn't exist or its status shows
		// something other than "exited", "paused", or "running", or if we ran into trouble
		// restarting it
		log.Info("Creating new container", "containerName", containerName)
		if err := createContainer(containerName, info.Info.ConfigDir); err != nil {
			return common.NewBasicError("Creating container", err, "containerName", containerName)
		}
	}

	log.Info("All containers started successfully")
	return nil
}

func promptUser(s string) bool {
	for {
		fmt.Println(s, "[y/n]")
		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Error("Reading user input", "err", err)
		}
		input = strings.TrimSpace(input)

		if utils.StringInSlice(input, []string{"yes", "y"}) {
			return true
		}
		if utils.StringInSlice(input, []string{"no", "n"}) {
			return false
		}
		fmt.Println("Unrecognized response, please answer with yes/y or no/n")
	}
}

// createContainer creates a new container using the docker.sh script in the SCION repo with the specified name
// and mounts the mountDirPath.
func createContainer(containerName string, mountDirPath string) error {
	// set the mount directory asID the gen directory we found
	if err := os.Setenv("SCION_MOUNT", mountDirPath); err != nil {
		return common.NewBasicError("Setting SCION_MOUNT env variable", err)
	}
	if err := os.Setenv("SCION_CNTR", containerName); err != nil {
		return common.NewBasicError("Setting SCION_MOUNT env variable", err)
	}

	// make the new containers through docker.sh
	cmd := exec.Command("./docker.sh", "start")
	cmd.Dir = os.Getenv("SC")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return common.NewBasicError("Running docker.sh start", err,
			"output", string(output))
	}
	return nil
}

// startContainer starts stopped or paused containers and starts supervisord on them.
func startContainer(container types.ContainerJSON, cl *client.Client) error {
	if container.State.Status == "exited" {
		log.Info("Found Container built but exited, starting container... ", "containerName", container.Name)
	}
	if err := cl.ContainerStart(context.Background(), container.ID, types.ContainerStartOptions{}); err != nil {
		return common.NewBasicError("Starting container", err)
	}
	// run supervisord
	execConfig := types.ExecConfig{
		User:         "scion",
		AttachStderr: true,
		AttachStdout: true,
		Detach:       false,
		Env:          []string{"SC=/home/scion/go/src/github.com/scionproto/scion"},
		Cmd:          []string{"supervisord", "-c", "supervisor/supervisord.conf"},
	}

	if _, err := runCommandInContainer(cl, container.Name, nil, execConfig); err != nil {
		log.Error("Running command in container", "err", err)
	}

	return nil
}

// check initial check to see in SCION is running on the host machine, that docker is installed,
// builds the SCION docker images using docker.sh from the SCION repo, and verifies the parsed
// configuration file.
func check(topoConfig *conf.TopoConfig, cl *client.Client) error {
	cmd := exec.Command("./scion.sh", "status")
	cmd.Dir = os.Getenv("SC")

	output, err := cmd.CombinedOutput()
	if err != nil || len(output) != 0 {
		return common.NewBasicError("SCION is not running on host machine or ran into some trouble", err)
	}

	// docker
	if !utils.CommandExists("docker") {
		return common.NewBasicError("Docker not installed", nil)
	}

	// check docker base images and build if necessary
	if err := buildBaseImages(cl); err != nil {
		return common.NewBasicError("Checking SCION base images", err)
	}

	///check the configuration file parsed
	if err := verifyConfig(topoConfig); err != nil {
		return common.NewBasicError("Verifying topology configuration file", err)
	}

	return nil
}

// verifyConfig verfires the values in the parsed YAML configuration file
func verifyConfig(topoConfig *conf.TopoConfig) error {
	// check gen directory
	if topoConfig.GenDir == "" {
		return common.NewBasicError("gen directory must be specified", nil)
	}
	info, err := os.Stat(topoConfig.GenDir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return common.NewBasicError(fmt.Sprintf("%v is not a directory", topoConfig.GenDir), nil)
	}

	numberOfAPs := 0
	for _, AS := range topoConfig.ASes {
		AS.Info = new(conf.ASInfo)
		if strings.TrimSpace(strings.ToLower(AS.APStr)) == "true" {
			AS.Info.AP = true
			numberOfAPs++
		} else {
			AS.Info.AP = false
		}
	}
	if numberOfAPs != 1 {
		return common.NewBasicError("Number of attachment points is not 1 in the "+
			"topology YAML configuration file ", nil)
	}

	// Check subnet
	if topoConfig.Subnet == "" {
		return common.NewBasicError("Subnet must be specified", nil)
	}

	return nil
}

// dockerDefaultNetwork returns true if we are to use the default docker network.
func dockerDefaultNetwork() (ip net.IP, err error) {
	cmd := exec.Command("./tools/docker-ip")
	cmd.Dir = os.Getenv("SC")
	output, err := cmd.CombinedOutput()
	if err != nil {
		err = common.NewBasicError("Running $SC/tools/docker-ip", err)
		return
	}
	dockerDefaultIPStr := strings.TrimSpace(string(output))
	ip = net.ParseIP(dockerDefaultIPStr)
	return
}

func buildBaseImages(cl *client.Client) error {

	images, err := cl.ImageList(context.Background(), types.ImageListOptions{
		All:     false,
		Filters: filters.Args{},
	})
	if err != nil {
		return err
	}

	for _, image := range images {
		if utils.StringInSlice("scion:scionlab", image.RepoTags) {
			log.Trace("Found SCION image built")
			return nil
		}
	}

	log.Info("SCION docker image not built, building image...")
	// Build base image first
	cmd := exec.Command("./docker.sh", "base")
	cmd.Dir = os.Getenv("SC")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return common.NewBasicError("Building SCION base image", err)
	}
	// build scion image
	cmd.Args = []string{"build"}
	err = cmd.Run()
	if err != nil {
		return common.NewBasicError("Building SCION docker image", err)
	}

	return nil
}

// setGenDirs gets the gen directory for each of the ASes
func setGenDirs(genDirsPath string, asMap conf.ASMap) error {
	iaFiles := append(utils.FindFile("ia", genDirsPath), filepath.Join(os.Getenv("SC"), "gen", "ia"))
	for _, iaFile := range iaFiles {
		ia, err := ioutil.ReadFile(iaFile)
		if err != nil {
			return common.NewBasicError("Reading ia file", err)
		}

		AS, ok := asMap[strings.Replace(string(ia), "_", ":", -1)]
		if !ok {
			log.Warn("AS found in gen directory not defined in topology config file", "IA", string(ia))
			continue
		}

		AS.Info.ConfigDir = filepath.Dir(filepath.Dir(iaFile))
	}

	return nil
}

func runCommandInContainer(cli *client.Client, containerName string, writer io.Writer,
	execConfig types.ExecConfig) (string, error) {

	idResponse, err := cli.ContainerExecCreate(context.Background(), containerName, execConfig)
	if err != nil {
		return "", common.NewBasicError("Creating docker exec command", err, "container", containerName)
	}

	hijackedResponse, err := cli.ContainerExecAttach(context.Background(), idResponse.ID, types.ExecStartCheck{})
	if err != nil {
		return "", common.NewBasicError("Running command in container", err, "container", containerName)
	}
	defer hijackedResponse.Close()

	if writer != nil {
		if _, err := stdcopy.StdCopy(writer, writer, hijackedResponse.Reader); err != nil {
			return "", common.NewBasicError("Writing to log file", err)
		}
	} else {
		output := make([]byte, 2<<26)
		n, err := hijackedResponse.Reader.Read(output)
		if err != nil && err != io.EOF {
			return "", common.NewBasicError("Writing to output buffer ", err)
		}

		return string(output[8 : n+8]), nil
	}

	return "", nil
}
