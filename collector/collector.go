package collector

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/kaldughayem/dynlinks/conf"
	"github.com/kaldughayem/dynlinks/utils"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
)

var (
	stopLock sync.Mutex
)

// Measurements is the configuration values for the collector instance,
// it tells the collector which measurements to run on the topology.
type Measurements struct {
	Bandwidth     bool
	Latency       bool
	Paths         bool
	PathSwitching bool
	ResourceUsage bool
}

// Configuration is the configuration values for a collector instance
type Configuration struct {
	// The ASes to get paths to and measure link properties between.
	ASInfos map[string]conf.ASInfo
	// Links to perform measurements on.
	Links conf.Links
	// LocalAddress is the SCION address the collector instance should use to send and receive messages, it
	// should have the port set to zero so it uses any available port for each of the tools used.
	LocalAddress *snet.Addr
	// The path where the logs should be written (default="logs")
	LogsPath string
	// ReturnChan channel to signal when the collector exits.
	ReturnChan chan struct{}
	// ExitChan is a channel where a signal to exit the routine from the caller is received.
	ExitChan chan struct{}
	// SetupChan signal channel when setup is done.
	SetupChan chan struct{}
}

// Collector is in charge of collecting measurements for all the ASes and Links specified in ASInfos and Links
// structures.
// It runs different tools to measure the latency, bandwidth, available paths, and resource usage for each one of the
// Links and ASes.
type Collector struct {
	measurements *Measurements
	cfg          *Configuration
	processes    []string
	// stop is a flag which signals all running routines started by a collector instance to exit
	stop bool
	wg   sync.WaitGroup
	// The docker client
	cli *client.Client
}

// NewCollector creates a new logs collector instance.
func NewCollector(cfg *Configuration, measurements *Measurements) *Collector {
	l := &Collector{
		measurements: measurements,
		cfg:          cfg,
	}

	return l
}

// Run is the main processing loop for the collector instance.
func (c *Collector) Run() {
	var err error

	defer func() {
		c.cfg.ReturnChan <- struct{}{}
	}()

	if err = c.setup(); err != nil {
		log.Crit("[collector] Setup failed", "err", err)
		return
	}

	go c.exitFunction()

	if c.measurements.Latency {
		if err := c.measureLatency(); err != nil {
			log.Trace("Measuring latency", "err", err)
		}
	}

	if c.measurements.PathSwitching {
		c.wg.Add(1)
		go c.measurePathSwitching()
	} else {
		c.cfg.SetupChan <- struct{}{}
	}

	if c.measurements.Bandwidth {
		c.wg.Add(1)
		go c.measureBandwidth()
	}

	if c.measurements.Paths {
		c.wg.Add(1)
		go c.getPaths()
	}

	if c.measurements.ResourceUsage {
		c.wg.Add(1)
		go c.measureResourceUsage()
	}

	c.wg.Wait()

	log.Debug("Running aggregator...")
	// Run the aggregator
	AnalyzeResults(c.cfg.LogsPath)
}

func (c *Collector) exitFunction() {
	<-c.cfg.ExitChan
	defer log.LogPanicAndExit()
	stopLock.Lock()
	c.stop = true
	stopLock.Unlock()
	c.killRunningProcesses()
}

func (c *Collector) setup() error {
	var err error

	// Create a new docker API client with version 1.39 (maximum supported version)
	c.cli, err = client.NewClientWithOpts(client.WithVersion("1.39"))
	if err != nil {
		return common.NewBasicError("Getting docker API client", err)
	}

	// Create the log directory if it does not exists
	if err := utils.CheckAndCreateDir(c.cfg.LogsPath); err != nil {
		return err
	}

	for _, name := range []string{"path", "latency", "bandwidth"} {
		dirPath := filepath.Join(c.cfg.LogsPath, name)
		if err = os.Mkdir(dirPath, 0750); err != nil {
			return common.NewBasicError("Creating directory", err, "LogsPath", c.cfg.LogsPath,
				"name", name)
		}
	}

	return nil
}

// startBwServers starts the bwtestserver on all running containers using the default address for
// bwtestserver (<IA>,[127.0.0.1]:40002)
func (c *Collector) startBwServers() error {
	// Run bwtestserver on each of the docker containers
	for asID, info := range c.cfg.ASInfos {
		if info.AP {
			continue
		}

		config := types.ExecConfig{
			User:   "scion",
			Detach: true,
			Env:    []string{"SC=/home/scion/go/src/github.com/scionproto/scion"},
			Cmd:    []string{"/home/scion/go/bin/bwtestserver", "-id", asID},
		}

		cntName := strings.Replace(asID, ":", "_", -1)

		idResponse, err := c.cli.ContainerExecCreate(context.Background(), cntName, config)
		if err != nil {
			return common.NewBasicError("Creating bwtestserver command", err, "container", cntName)
		}

		err = c.cli.ContainerExecStart(context.Background(), idResponse.ID, types.ExecStartCheck{
			Detach: true,
			Tty:    false,
		})
		if err != nil {
			return common.NewBasicError("Starting bwtestserver", err, "container", cntName)
		}

	}
	return nil
}

// measureLatency starts sending SCMP echo requests every second on each link (one SCMP measurement per link) to measure
// RTT and total loss on that link.
func (c *Collector) measureLatency() error {
	scmpPath := filepath.Join("bin", "scmp")
	c.processes = append(c.processes, "scmp")

	for linkName, link := range c.cfg.Links {
		logName := filepath.Join(c.cfg.LogsPath, "latency", linkName+".log")
		// If the file doesn't exist, create it, or append to the file
		f, err := os.OpenFile(logName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return common.NewBasicError("Creating log file", err, "file", logName)
		}
		// Should not include port for scmp tool
		srcAddress := fmt.Sprintf("%s,[%s]", link.ASA, c.cfg.LocalAddress.Host.L3.String())
		dstAddress := fmt.Sprintf("%s,[127.0.0.1]", link.ASB)
		args := []string{"echo", "-local", srcAddress, "-remote", dstAddress, "-refresh"}

		c.wg.Add(1)
		go func(args []string, AS string, f os.File, wg *sync.WaitGroup) {
			defer f.Close()
			for !c.getStop() {
				if c.cfg.ASInfos[AS].AP {
					if err := runCmdLocally(scmpPath, args, &f); err != nil {
						// The error is logged in the file
						//log.Error("Running latency command locally", "AS", AS)
						time.Sleep(time.Second)
					}
				} else {
					containerName := strings.Replace(AS, ":", "_", -1)
					cmd := append([]string{scmpPath}, args...)
					if err := runCmdInContainer(c.cli, containerName, cmd, &f); err != nil {
						log.Error("Running latency command on container", "AS", AS)
						time.Sleep(time.Second)
					}
				}
			}
			wg.Done()
		}(args, link.ASA, *f, &c.wg)
	}

	time.Sleep(time.Second)
	return nil
}

func (c *Collector) getPaths() {
	defer c.wg.Done()
	c.processes = append(c.processes, "showpaths")

	var wg sync.WaitGroup

	for srcIA, info := range c.cfg.ASInfos {

		// Set the address and baseArguments
		address := fmt.Sprintf("%s,%s", srcIA, c.cfg.LocalAddress.Host.String())
		baseArgs := []string{"-refresh", "-expiration", "-maxpaths", "10", "-timeout", "3s", "-p",
			"-local", address}
		logName := filepath.Join(c.cfg.LogsPath, "path", srcIA+".log")
		// If the file doesn't exist, create it, or append to the file
		f, err := os.OpenFile(logName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			log.Error("Creating log file", "err", err, "file", logName)
			return
		}

		// Range over possible destination ASes and run each on AS in different goroutine
		wg.Add(1)
		go c.singlePathMeasurement(srcIA, info, baseArgs, *f, &wg)
	}
	wg.Wait()
}

func (c *Collector) singlePathMeasurement(srcIA string, info conf.ASInfo, baseArgs []string, f os.File,
	wg *sync.WaitGroup) {
	defer wg.Done()
	defer f.Close()
	var err error
	showPaths := filepath.Join("bin", "showpaths")

	for !c.getStop() {
		for dstIA := range c.cfg.ASInfos {
			if dstIA == srcIA {
				continue
			}
			separator := fmt.Sprintf("%s dstIA=%s time=%s\n", strings.Repeat("#", 5),
				dstIA, time.Now().Format(time.RFC3339Nano))
			if _, err = f.WriteString(separator); err != nil {
				log.Error("Writing separator to file", "file", f.Name(), "err", err)
			}
			args := append([]string{"-srcIA", srcIA, "-dstIA", dstIA}, baseArgs...)
			if info.AP {
				// ignore the error because it will be logged to the file
				// #nosec
				_ = runCmdLocally(showPaths, args, &f)

			} else { // run the command on container
				cmd := append([]string{showPaths}, args...)
				containerName := strings.Replace(srcIA, ":", "_", -1)
				if err = runCmdInContainer(c.cli, containerName, cmd, &f); err != nil {
					log.Error("Getting paths from container", "dst", dstIA)
				}
			}
		}
	}
}

// measureResourceUsage gets the docker stats and then the running SCION processes using th ps command .
func (c *Collector) measureResourceUsage() {
	defer c.wg.Done()

	logName := filepath.Join(c.cfg.LogsPath, "resource_usage.log")
	// If the file doesn't exist, create it, or append to the file
	f, err := os.OpenFile(logName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Error("Creating log file", "file", logName, "err", err)
		return
	}
	defer f.Close()

	dockerStatsArgs := []string{"stats", "--no-stream"}
	for as, info := range c.cfg.ASInfos {
		if info.AP { // Not a docker container
			continue
		}
		dockerStatsArgs = append(dockerStatsArgs, strings.Replace(as, ":", "_", -1))
	}

	for !c.getStop() {
		separator := fmt.Sprintf("%s time=%s\n", strings.Repeat("#", 10), time.Now().UTC().String())
		if _, err := f.WriteString(separator); err != nil {
			log.Error("Writing to log file", "err", err, "file", f.Name())
			return
		}

		if err := runCmdLocally("docker", dockerStatsArgs, f); err != nil {
			log.Error("Running docker stats command", "err", err)
			return
		}

		// Get the running processes along with their cpu and memory usage
		if _, err := f.WriteString("# Processes\n"); err != nil {
			log.Error("Writing to log file", "err", err, "file", f.Name())
			return
		}

		if err := runCmdLocally("ps", []string{"-C",
			"border,cert_srv,path_srv,beacon_server,sciond,bwtestserver", "-o", "pid,ppid,%mem,%cpu,cmd"},
			f); err != nil {
			log.Error("Running docker stats command", "err", err)
			return
		}
	}
}

// measureBandwidth runs the bandwidth clients to measure the bandwidth on every link.
func (c *Collector) measureBandwidth() {
	defer c.wg.Done()

	c.processes = append(c.processes, "bwtestclient", "bwtestserver")

	var wg sync.WaitGroup

	if err := c.startBwServers(); err != nil {
		log.Error("Starting bandwidth server (bwtestserver) on containers", "err", err)
		return
	}
	defer func() {

	}()
	for linkName, link := range c.cfg.Links {
		logName := filepath.Join(c.cfg.LogsPath, "bandwidth", linkName+".log")

		// If the file doesn't exist, create it, or append to the file
		f, err := os.OpenFile(logName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			log.Error("Creating/Opening log file", "err", err, "file", logName)
			return
		}

		wg.Add(1)
		go c.singleBandwidthMeasurement(*f, *link, &wg)
	}
	wg.Wait()
}

// singleBandwidthMeasurement starts the continuous bandwidth measurements on a single link.
func (c *Collector) singleBandwidthMeasurement(f os.File, link conf.Link, wg *sync.WaitGroup) {
	defer wg.Done()
	defer f.Close()

	for !c.getStop() {
		dstAddress := fmt.Sprintf("%s,[127.0.0.1]:40002", link.ASB)

		var args []string
		if link.Properties.Rate != "" { // if the rate is set for the link, then set the bandwidth to try to
			// double the set bandwidth rate
			newRate, err := setBandwidth(link.Properties.Rate)
			if err != nil {
				log.Error("Setting bandwidth rate", "err", err)
				return
			}
			args = []string{"-s", dstAddress, "-cs", newRate}
		} else {
			args = []string{"-s", dstAddress, "-cs", "10Mbps"}
		}

		if c.cfg.ASInfos[link.ASA].AP {
			// dstAddress is based` on the AS we are running in, if it is the AP and the parent link then we need to
			// set the address as the default bwtestserver address for that attachment point.
			if link.Type == proto.LinkType_parent {
				args[1] = fmt.Sprintf("%s,[10.0.8.1]:30100", link.ASB)
			}

			// Let us know if a measurement is taking too long
			timer := time.NewTimer(time.Minute)
			go func() {
				<-timer.C
				log.Warn("Single bandwidth measurement been running for longer than a minute!",
					"link", link.ASA+"_"+link.ASB)
				// TODO handle the situation by terminating the process or returning from the caller
				//  function if the bwtesterclient locks
			}()
			bwtestClientPath := filepath.Join(os.Getenv("GOPATH"), "bin", "bwtestclient")
			// #nosec
			_ = runCmdLocally(bwtestClientPath, args, &f)
			timer.Stop()
		} else {
			cmd := append([]string{"/home/scion/go/bin/bwtestclient"}, args...)
			containerName := strings.Replace(link.ASA, ":", "_", -1)

			if err := runCmdInContainer(c.cli, containerName, cmd, &f); err != nil {
				log.Error("Running bwtestclient in docker", "container", containerName, "dst",
					dstAddress)
			}
		}
		if _, err := f.WriteString(strings.Repeat("#", 10) + "\n"); err != nil {
			log.Error("Writing separator to file", "file", f.Name(), "err", err)
		}
	}
}

// TODO change later to find maxBandwidth instead when it is merged
func setBandwidth(rate string) (string, error) {
	rateStr := regexp.MustCompile(`\d+`).FindString(rate)
	newRate, err := strconv.ParseUint(rateStr, 10, 64)
	if err != nil {
		return "", err
	}
	newRate *= 2

	newRateStr := fmt.Sprintf("%d%s", newRate, regexp.MustCompile(`[MmGgTtKk]?(bps|bit/s)`).
		FindString(rate))
	return newRateStr, nil
}

// killRunningProcesses kills SCMP echo, bwtester servers and clients. Only used on exit.
func (c *Collector) killRunningProcesses() {
	log.Trace("killing running collector processes")
	for _, p := range c.processes {
		if err := exec.Command("pkill", p).Run(); err != nil {
			log.Error("killing process", "process name", p, "err", err)
		}
	}

	if c.measurements.Bandwidth {
		// TODO check first if BR is still hogging the CPU because of bwtester
		out, err := exec.Command("pkill", "-SIGTERM", "border").Output()
		if err != nil {
			log.Error("Sending SIGTERM to Border router", "err", err)
		}
		log.Trace("Killed BR with SIGTERM", "output", string(out))
	}
}

// measurePathSwitching pings, or retrieves the paths to an AS which has more than one path
// continuously, to check how fast path switching occurs when a path goes down
// or when a new one comes up.
func (c *Collector) measurePathSwitching() {
	// Find the AS with more than two paths from the AP
	dstIA := findMultipathAS(c.cfg.ASInfos, c.cfg.LocalAddress)
	if dstIA == "" {
		log.Warn("No AS with more than one path available is found in the topology, " +
			"Path switching measurements are not running.")

		// signal collector caller that setup is finished
		c.cfg.SetupChan <- struct{}{}

		return
	}
	// Setup the addresses and cmd paths
	dstAddress := fmt.Sprintf("%s,[127.0.0.1]", dstIA)
	scmpPath := filepath.Join("bin", "showpaths")
	logName := filepath.Join(c.cfg.LogsPath, "measurePathSwitching.log")

	// If the file doesn't exist, create it, or append to the file
	f, err := os.OpenFile(logName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Error("Creating log file", "err", err, "file", logName)
		return
	}
	defer f.Close()

	log.Trace("Path switching measurements are running", "dst", dstAddress)

	// signal collector caller that setup is finished
	c.cfg.SetupChan <- struct{}{}

	for !c.getStop() {
		separator := fmt.Sprintf("%s time=%s\n", strings.Repeat("#", 5),
			time.Now().Format(time.RFC3339Nano))
		if _, err := f.WriteString(separator); err != nil {
			log.Error("Writing separator to the file", "err", err)
			continue
		}
		// do not check the path health because we just want to query for the paths.
		args := []string{"-dstIA", dstIA, "-srcIA", c.cfg.LocalAddress.IA.String(), "-refresh"}
		_ = runCmdLocally(scmpPath, args, f)
		time.Sleep(time.Millisecond * 500)
	}

	c.wg.Done()
}

// runCmdInContainer runs a command inside a docker container.
func runCmdInContainer(cli *client.Client, containerName string, cmd []string, writer io.Writer) error {
	execConfig := types.ExecConfig{
		User:         "scion",
		AttachStderr: true,
		AttachStdout: true,
		Detach:       true,
		Env:          []string{"SC=/home/scion/go/src/github.com/scionproto/scion"},
		Cmd:          cmd,
	}

	idResponse, err := cli.ContainerExecCreate(context.Background(), containerName, execConfig)
	if err != nil {
		return common.NewBasicError("Creating docker exec command", err, "container", containerName)
	}

	hijackedResponse, err := cli.ContainerExecAttach(context.Background(), idResponse.ID, types.ExecStartCheck{})
	if err != nil {
		return common.NewBasicError("Running command in container", err, "container", containerName)
	}
	defer hijackedResponse.Close()

	if writer != nil {
		if _, err := stdcopy.StdCopy(writer, writer, hijackedResponse.Reader); err != nil {
			return common.NewBasicError("Writing to log io writer", err)
		}
	} else {
		if _, err := stdcopy.StdCopy(os.Stdout, os.Stderr, hijackedResponse.Reader); err != nil {
			return common.NewBasicError("Writing to standard output", err)
		}
	}

	return nil
}

// runCmdLocally runs a command on the hosts machine.
func runCmdLocally(cmdPath string, args []string, writer io.Writer) error {
	// TODO (packages) need to find a way to run the tools without the scion dir
	cmd := exec.Command(cmdPath, args...)
	cmd.Dir = os.Getenv("SC")
	if writer != nil {
		cmd.Stdout = writer
		cmd.Stderr = writer
	} else {
		cmd.Stderr = os.Stdout
		cmd.Stdout = os.Stderr
	}

	err := cmd.Run()
	if err != nil {
		return common.NewBasicError("Executing command locally", err)
	}
	return nil

}

// findMultipathAS finds an AS with more than one path available from the
// LocalAddress specified to one of the ASes in the ASInfos passed (usually
// the containerized ASes)
func findMultipathAS(asInfos conf.ASInfos, localAddress *snet.Addr) string {
	// TODO (packages) need to find a way to run the tools without the scion dir
	for dstIA := range asInfos {
		showPaths := filepath.Join("bin", "showpaths")
		args := []string{"-srcIA", localAddress.IA.String(), "-dstIA", dstIA, "-refresh"}
		cmd := exec.Command(showPaths, args...)
		cmd.Dir = os.Getenv("SC")
		output, err := cmd.CombinedOutput()

		if err != nil {
			log.Error("Could not retrieve paths for comparisons, command returned error", "dstIA", dstIA,
				"err", err)
			continue
		}

		paths := make([]string, 0)
		availablePaths := regexp.MustCompile(`(?m)\[ \d+].*\n`).FindAllString(string(output), -1)
		if len(availablePaths) == 0 {
			continue
		}

		for _, rawPath := range availablePaths {
			path := regexp.MustCompile(PathRegex).FindString(rawPath)
			path = strings.Trim(path, "[]")
			if utils.StringInSlice(path, paths) {
				continue
			}
			paths = append(paths, path)
		}
		// if more than 2 paths are available, return AS IA
		if len(paths) > 1 {
			return dstIA
		}
	}

	return ""
}

func (c *Collector) getStop() bool {
	stopLock.Lock()
	v := c.stop
	stopLock.Unlock()
	return v
}
