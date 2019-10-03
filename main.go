package main

import (
	"flag"
	"fmt"
	"github.com/kaldughayem/dynlinks/collector"
	"github.com/kaldughayem/dynlinks/conf"
	"github.com/kaldughayem/dynlinks/modiface"
	"github.com/kaldughayem/dynlinks/topomaker"
	"github.com/kaldughayem/dynlinks/ui"
	"github.com/kaldughayem/dynlinks/utils"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/env"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/proto"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	expFlags = flag.NewFlagSet("exp", flag.ExitOnError)
	duration = expFlags.Duration("t", 0, "(optional) The time duration to run the experiment for. "+
		"(default=0 continuous)")
	genDir = expFlags.String("gen", "", "Path to the directory containing all docker"+
		" gen directories")
	interactive = expFlags.Bool("i", false, "Run the in interactive mode.")
	properties  = expFlags.String("p", "", "Links' properties file which has the properties "+
		"for each link in the topology. \nWill run according to the properties specified for each link in the "+
		"file.\nIt should not be used with the interactive mode.\nTo get a base properties file based on the parsed "+
		"gen directory use the -o option.")
	output = expFlags.String("o", "", "Output a base properties YAML file to represent the links based "+
		"on the gen directory and exit.")
	addressStr = expFlags.String("local", "", "(optional) the host address to use when "+
		"communicating over SCION.\nIt is highly recommended to use a loop back address so that it works for ASes "+
		"in the docker topology as well.\n(default=<ap IA>,[127.0.0.42] the port should not be specified)")
	logLevel = expFlags.String("log", "debug", "Log console's level.")
	id       = expFlags.String("id", "", "The experiment id and where to save the log "+
		"files for the experiment.")
	alternate = expFlags.Bool("alternate", false, "Make revocations alternate when the period is set "+
		"by waiting for the specified period of the first revocation\nbefore starting the second revocation,and "+
		"the same before starting the third (if there is three revoked\ninterfaces) and so on.")
	measurementsConfigPath = expFlags.String("m", "", "A collector measurements "+
		"configuration YAML file that tells the collector module which measurements\nto collect on the topology"+
		" during the experiment.")
)

var (
	links   conf.Links
	asInfos map[string]conf.ASInfo
	// The Address for both the modiface and collector use for communication.
	address *snet.Addr
	// exitChan is th channel to close to exit all running go routines.
	exitChan chan struct{}
	// Channel to waitChan on signal from all goroutines to exit an cleanup after exit.
	waitChan []chan struct{}
	logsPath string
)

func main() {
	var err error

	if len(os.Args) < 2 {
		fmt.Println("usage: dynlinks <command> [<args>]")
		fmt.Println("Commands: ")
		fmt.Println(" topo		run topomaker and create a new topology based on a topology config file")
		fmt.Println(" exp		to output empty links file, run an experiment based on given links YAML file, " +
			"or set link properties in interactive mode then run an experiment")
		os.Exit(1)
	}
	switch os.Args[1] {
	case "topo":
		topomakerFlags := flag.NewFlagSet("topo", flag.ExitOnError)
		topologyConfig := topomakerFlags.String("config", "", "The topology configuration YAML file "+
			"to create new topology based on it")
		buildApps := topomakerFlags.Bool("buildApps", false, "Build the SCION apps inside the "+
			"containers")
		logLevel := topomakerFlags.String("log", "info", "Console log level")
		output := topomakerFlags.String("o", "", "Output a base properties YAML file to "+
			"represent the links based on the newly created topology.")
		id := topomakerFlags.String("id", "", "The log files identifier (default=topomaker).")
		// setup logging
		if err := topomakerFlags.Parse(os.Args[2:]); err != nil {
			log.Crit("Parsing topology maker flags failed", "err", err)
			os.Exit(1)
		}
		if err := setupLogging(*id, *logLevel); err != nil {
			log.Crit("Setting up logging", "err", err)
			os.Exit(1)
		}
		topomaker.Run(*topologyConfig, *output, *buildApps)

	case "exp":
		if err := expFlags.Parse(os.Args[2:]); err != nil {
			log.Crit("Parsing flags failed", "err", err)
			os.Exit(1)
		}

	default:
		log.Crit("unrecognized command")
		fmt.Println("usage: dynlinks <command> [<args>]")
		fmt.Println("Commands: ")
		fmt.Println(" topo		run topomaker and create a new topology based on a topology config file")
		fmt.Println(" exp		to output empty links file, run an experiment based on given links YAML file, " +
			"or set link properties in interactive mode then run an experiment")
		os.Exit(2)
	}

	if err = setup(); err != nil {
		log.Crit("Setup failed", "err", err)
		os.Exit(1)
	}

	// Save properties to file and exit
	if *output != "" {
		if err := utils.OutputProperties(*output, *genDir); err != nil {
			log.Error("Generating empty links' properties file", "err", err)
		}
		os.Exit(0)
	}

	// Init the local address
	if *addressStr == "" {
		var IA string
		for AS, info := range asInfos {
			if info.AP {
				IA = AS
				break
			}
		}
		*addressStr = fmt.Sprintf("%s,[127.0.0.42]", IA)
		log.Debug("Using default address", "host", *addressStr)
	}
	address, err = snet.AddrFromString(*addressStr)
	if err != nil {
		log.Crit("Setting up address", "err", err)
		os.Exit(1)
	}
	address.Host.L4 = addr.NewL4UDPInfo(0)

	// Init the global vars
	links = make(conf.Links)
	exitChan = make(chan struct{})
	waitChan = make([]chan struct{}, 0)

	// Catch user interrupt
	utils.SetupSignals(func() {
		log.Debug("Captured Interrupt")
		closeExitChan()
	})

	if *interactive {
		// Construct links structure
		if err := conf.BuildLinks(links, asInfos); err != nil {
			log.Error("Building links failed", "err", err)
		}

		ui.HandleInteractive(links)
	} else {
		// Properties file is set, fill properties file based on it
		if err := utils.LoadYAML(*properties, &links); err != nil {
			log.Crit("Loading properties", "err", err)
			os.Exit(1)
		}
		// check the properties parsed from file
		for id, link := range links {
			if err := utils.ValidateProperties(&link.Properties); err != nil {
				log.Crit("Validating properties, use the -o option to save a sample links' properties json file and "+
					"modify that file", "link", id, "err", err)
				os.Exit(1)
			}
		}
		log.Info("Links loaded and validated from file")
	}

	// log the running time each minute
	go logTime()

	if *measurementsConfigPath != "" {
		startCollector()
	}

	// start the modiface instances needed
	startModiface()

	log.Info("Experiment started", "time", time.Now())
	// if the duration is set, then signal the running goroutines after the duration expires
	if *duration > 0 {
		go time.AfterFunc(*duration, func() {
			log.Debug("Timer expired, exiting")
			// close the exit channel to signal the other running go routines to exit
			closeExitChan()
		})
	}

	var wg sync.WaitGroup
	// Wait goroutines to terminate
	for _, c := range waitChan {
		wg.Add(1)
		go func(wg *sync.WaitGroup, c chan struct{}) {
			<-c
			wg.Done()
		}(&wg, c)
	}
	wg.Wait()
	log.Info("Finished experiment")
}

func startCollector() {
	// If not set, then by default all measurements should be off
	measurements := &collector.Measurements{}

	if err := utils.LoadYAML(*measurementsConfigPath, measurements); err != nil {
		log.Crit("Loading the collector YAML configuration", "err", err)
		os.Exit(1)
	}

	c := make(chan struct{})
	waitSetup := make(chan struct{})

	collectorConfig := &collector.Configuration{
		ASInfos:      asInfos,
		Links:        links,
		LocalAddress: address,
		LogsPath:     logsPath,
		ReturnChan:   c,
		ExitChan:     exitChan,
		SetupChan:    waitSetup,
	}

	l := collector.NewCollector(collectorConfig, measurements)
	waitChan = append(waitChan, c)
	log.Debug("Starting collector...")
	go l.Run()
	// Wait for collector to finish setup and start logging
	<-waitSetup
}

func startModiface() {
	// 	Start modiface goroutines to modify links according to the properties
	for id, l := range links {
		ap := asInfos[l.ASA].AP
		var m *modiface.Modiface
		var activeAS addr.IA
		var activeIFID common.IFIDType
		var err error
		if l.Properties == conf.DefaultProperties() {
			continue
		}

		c := make(chan struct{})

		activeIFID, activeAS, err = handleLinkType(l, ap, id)
		if err != nil {
			log.Crit("Parsing IA address from string, this shouldn't happen", "err", err)
			close(exitChan)
			return
		}

		log.Debug("Starting modiface", "ID", id)
		modifaceConfig := &modiface.Config{
			ID:         id,
			ActiveAS:   activeAS,
			IFID:       activeIFID,
			Properties: &l.Properties,
			LocalAddr:  address,
			ASInfos:    asInfos,
			ReturnChan: c,
			ExitChan:   exitChan,
		}

		m = modiface.NewModiface(modifaceConfig)
		waitChan = append(waitChan, c)
		go m.Run()

		// To make the links do a blinking like manner with the revocation
		if l.Properties.RevocationPeriod > 0 && l.Properties.Revoke && *alternate {
			time.Sleep(l.Properties.RevocationPeriod)
		} else {
			time.Sleep(time.Second)
		}
	}

}

func handleLinkType(l *conf.Link, ap bool, id string) (activeIFID common.IFIDType, activeAS addr.IA, err error) {
	if l.Type == proto.LinkType_parent && !ap {
		// Modify the link from the parent's side so we do not lose connectivity
		activeIFID = l.IfidB
		activeAS, err = addr.IAFromString(l.ASB)
	} else if l.Type > 4 || l.Type < 1 {
		log.Crit("Link type error when running modiface", "link", id, "type", l.Type.String())
		close(exitChan)
		return
	} else {
		activeIFID = l.IfidA
		activeAS, err = addr.IAFromString(l.ASA)
	}

	return
}

// Check if the SCION applications to be used are built on the host
func appsBuilt() bool {
	apps := []string{"bwtestserver", "bwtestclient"}
	for _, app := range apps {
		pathToApps := filepath.Join(os.Getenv("GOPATH"), "bin", app)
		if _, err := os.Stat(pathToApps); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func checkFlags() error {
	if *genDir == "" {
		return common.NewBasicError("gen directory must be specified when in interactive or output mode", nil)
	}

	info, err := os.Stat(*genDir)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		return common.NewBasicError(fmt.Sprintf("%v is not a directory", *genDir), nil)
	}

	if err = checkFlagsCombination(); err != nil {
		return err
	}

	return nil
}

func checkFlagsCombination() error {
	if (*interactive && (*properties != "" || *output != "")) || (*output != "" && *properties != "") {
		return common.NewBasicError("Cannot set properties file, or output flag, and interactive mode at the "+
			"same time. Please choose one.", nil)
	}

	if !*interactive && *properties == "" && *output == "" {
		return common.NewBasicError("Must set one of the flags", nil)
	}

	return nil
}

func setup() error {
	if err := setupLogging(*id, *logLevel); err != nil {
		fmt.Printf("Log Setup failed err=\"%s\"\n", err)
		os.Exit(1)
	}

	if err := checkFlags(); err != nil {
		flag.Usage()
		return common.NewBasicError("Flag validation failed", err)
	}

	// Check if tcconfig is installed
	if !utils.CommandExists("tcset") {
		return common.NewBasicError("tcconfig not installed. Please install tcconfig using the following "+
			"command:\n\tpip install tcconfig\n or run the deps.sh script.", nil)
	}

	// Are SCION apps built
	if !appsBuilt() {
		return common.NewBasicError("SCION apps are not installed. Please run deps.sh to install them.",
			nil)
	}

	asInfos = make(conf.ASInfos)
	if err := utils.SetASInfo(*genDir, asInfos); err != nil {
		return common.NewBasicError("Loading AS infos from the gen directory", err)
	}

	return nil
}

// setupLogging setup logging, and creates the needed directories
func setupLogging(experimentID, logLevel string) error {
	if err := utils.CheckAndCreateDir("logs"); err != nil {
		return err
	}
	cfg := struct {
		env.Logging
	}{}

	if experimentID == "" {
		experimentID = "experiment"
	}
	logsPath = filepath.Join("logs", experimentID)
	if _, err := os.Stat(logsPath); err == nil {
		logsPath = fmt.Sprintf("%s_%s", logsPath, time.Now().Format(time.RFC3339))
	}
	if err := os.Mkdir(logsPath, 0750); err != nil {
		return common.NewBasicError("Creating directory", err)
	}

	consoleLevel := strings.ToLower(logLevel)
	cfg.Logging.Console.Level = consoleLevel
	cfg.Logging.File.Path = filepath.Join(logsPath, "dynlinks.log")
	cfg.Logging.File.Level = "trace"
	if err := env.InitLogging(&cfg.Logging); err != nil {
		return err
	}

	info := fmt.Sprintf("========> Starting Dynamic Links \n\t%s\n\t%s\n\t%s\n\t%s\n",
		fmt.Sprintf("Experiment ID: 	%s", experimentID),
		fmt.Sprintf("Properties file: %s", *properties),
		fmt.Sprintf("Duration:	%s", duration.String()),
		fmt.Sprintf("cmd line:      	%q", os.Args),
	)

	log.Info(info)
	return nil
}

func logTime() {
	ticker := time.NewTicker(time.Minute)
	before := time.Now()
	for {
		select {
		case <-ticker.C:
			log.Trace("One minute passed", "running time", time.Since(before))
		case <-exitChan:
			ticker.Stop()
			return
		}
	}
}

func closeExitChan() {
	select {
	case <-exitChan:
		return
	default:
		close(exitChan)
	}
}
