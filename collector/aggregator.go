package collector

import (
	"fmt"
	"github.com/kaldughayem/dynlinks/utils"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/log"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// IA is the regex for IA addresses
	IA = `\d+-[[:xdigit:]]+:[[:xdigit:]]+:[[:xdigit:]]+`
)

var (
	pathRegex = fmt.Sprintf(`(?m)\[%s \d+>(\d+ %s \d+>)*\d+ %s\]`, IA, IA, IA)
	file      *os.File
)

// AnalyzeResults aggregates the logs from the collector located in the passed logsDir.
// It outputs a file in the logsDir with the results, if it can't create or write to the
// file then it prints the results to standard output.
func AnalyzeResults(logsDir string) {
	var err error
	logFileName := filepath.Join(logsDir, "aggregated_results.log")
	file, err = os.Create(logFileName)
	if err != nil {
		log.Error("Cannot create aggregator log file, using only main log file", "err", err)
	}
	defer file.Close()

	if err := filepath.Walk(logsDir, walkFunction); err != nil {
		log.Error("Walking directory", "err", err, logsDir)
		return
	}
}

func walkFunction(path string, info os.FileInfo, err error) error {
	if !info.IsDir() { // process log files based ion their parent dir name
		subDirectory := filepath.Base(filepath.Dir(path))
		switch subDirectory {
		case "bandwidth":
			aggregatorLogger("\nBandwidth analysis of file: " + info.Name() + processBandwidthFiles(path))
		case "latency":
			aggregatorLogger("\nLatency analysis of file: " + info.Name() + processLatencyFiles(path))
		case "path":
			aggregatorLogger("\nPath analysis of file: " + info.Name() + processPathsFiles(path))
			processPathsFiles(path)
		default:
			if info.Name() == "measurePathSwitching.log" {
				aggregatorLogger("\nPath switcher log analysis: " + processPathSwitcherFile(path))
			} else if info.Name() == "resource_usage.log" {
				// TODO more processing on the resource usage files
				log.Warn("Resource usage log analysis not implemented yet.")
			}
		}
	}
	return nil
}

func aggregatorLogger(s string) {
	if file != nil {
		if _, err := file.WriteString(s); err != nil {
			log.Error("[aggregator] Writing to file", "err", err)
			log.Info(s)
		}
	} else {
		log.Info(s)
	}
}

func processPathSwitcherFile(fileName string) string {
	//#nosec
	raw, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Error("Reading latency file", "file", fileName, "err", err)
	}

	type pingerStats struct {
		paths     []string
		timestamp time.Time
	}

	//var stats []pingerStats
	var prevEntry pingerStats
	var info string

	trimmed := trimJunk(string(raw))

	i := 0
	for _, block := range regexp.MustCompile(`[#]+ ([^#].*\n)+`).FindAllString(trimmed, -1) {
		// Parse the time
		line := regexp.MustCompile(`^[#]+ time=.*\n`).FindString(block)
		timeStr := strings.Split(line, "=")[1]
		t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(timeStr))
		if err != nil {
			log.Error("Parsing time from measurePathSwitching entry", "err", err)
		}
		entry := pingerStats{
			paths:     make([]string, 0),
			timestamp: t,
		}

		// Get the available paths from the block
		availablePaths := regexp.MustCompile(`(?m)\[ \d+].*\n`).FindAllString(block, -1)

		for _, rawPath := range availablePaths {

			path := regexp.MustCompile(pathRegex).FindString(rawPath)
			path = strings.Trim(path, "[]")

			// Check if the path is already appended (only collect unique paths)
			if utils.StringInSlice(path, entry.paths) {
				continue
			}
			entry.paths = append(entry.paths, path)
		}

		//stats = append(stats, entry)

		if i == 0 {
			i++
			prevEntry = entry
			continue
		}

		if utils.SlicesEqual(entry.paths, prevEntry.paths) {
			prevEntry = entry
			continue
		} else {
			info = fmt.Sprintf("%s\n\tPaths Entries difference: \n"+
				"\t\tPrevious time:		%s\n"+
				"\t\tPrevoious paths: 	%s\n"+
				"\t\tLatter time:		%s\n"+
				"\t\tLatter paths:		%s\n"+
				"\t\tTime difference:	%s\n",
				info, prevEntry.timestamp, prevEntry.paths, entry.timestamp.String(), entry.paths,
				entry.timestamp.Sub(prevEntry.timestamp).String())
		}
		prevEntry = entry
		i++
	}

	if info == "" {
		return "\nNo path differences found in log file"
	}
	return info

}

func processPathsFiles(fileName string) string {
	//#nosec
	raw, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Error("Reading latency file", "file", fileName, "err", err)
	}
	// Trim the Ctrl and non-ascii characters from the
	trimmed := trimJunk(string(raw))

	type pathStats struct {
		paths     []string
		timestamp time.Time
		toAS      string
	}
	//var pathStatsMap []pathStats
	var info string

	blocks := regexp.MustCompile(`[#]+ ([^#].*\n)+`).FindAllString(trimmed, -1)
	for _, block := range blocks {
		// Parse the timestamp of this measurement
		line := regexp.MustCompile(`time=(.*)`).FindString(block)
		t, err := time.Parse(time.RFC3339Nano, strings.Split(line, "=")[1])
		if err != nil {
			log.Error("Parsing the time from string ", "err", err)
			continue
		}

		// Parse the destination we want to get the paths to
		toAS := strings.Split(regexp.MustCompile(`dstIA=`+IA).FindString(block), "=")[1]

		entry := pathStats{
			timestamp: t,
			toAS:      toAS,
			paths:     make([]string, 0),
		}
		// Get the available paths from the block
		availablePaths := regexp.MustCompile(`(?m)\[ \d+].*\n`).FindAllString(block, -1)
		if len(availablePaths) == 0 {
			//pathStatsMap = append(pathStatsMap, entry)
			continue
		}

		for _, rawPath := range availablePaths {
			// First check if path is alive
			status := regexp.MustCompile(`Status: (Alive|Unknown)`).FindString(rawPath)
			if status == "" {
				// If the status is not Alive or Unknown do not process the path
				continue
			}

			path := regexp.MustCompile(pathRegex).FindString(rawPath)
			path = strings.Trim(path, "[]")

			if utils.StringInSlice(path, entry.paths) {
				continue
			}
			entry.paths = append(entry.paths, path)
		}

		//pathStatsMap = append(pathStatsMap, entry)

		info = fmt.Sprintf("%s\n\tPath Entry: \n"+
			"\t\tTime:			%s\n"+
			"\t\tTo AS:			%s\n"+
			"\t\tAvailable paths:	%s\n",
			info, entry.timestamp.Format(time.RFC3339Nano), entry.toAS, entry.paths)
	}

	if info == "" {
		return "\nNo path differences found in log file"
	}

	return info

}

func processLatencyFiles(fileName string) string {
	//#nosec
	raw, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Error("Reading latency file", "file", fileName, "err", err)
	}

	type latencyStats struct {
		seq   uint64
		delay time.Duration
	}

	var latencies []latencyStats
	var totalDelay = 0 * time.Second
	var totalDiff = 0 * time.Second

	re := regexp.MustCompile(`(?m)(scmp_seq=\d+) (time=\d+.\d*[m|µ]*s)\n`)

	i := 0
	for _, line := range re.FindAllString(string(raw), -1) {
		seq, err := strconv.ParseUint(strings.Split(strings.Split(line, " ")[0], "=")[1], 10, 64)
		if err != nil {
			log.Error("Converting seq number to int", "err", err)
			continue
		}
		delay, err := time.ParseDuration(strings.TrimSpace(strings.Split(strings.Split(line, " ")[1],
			"=")[1]))
		if err != nil {
			log.Error("Converting delay number to int", "err", err)
			continue
		}

		latencies = append(latencies, latencyStats{seq: seq, delay: delay})

		// Gather info for jitter and avg
		if i == 0 { // if it is the first element skip it
			totalDelay += delay
			i++
			continue
		}

		totalDelay += delay
		diff := delay - latencies[i-1].delay
		totalDiff += time.Duration(math.Abs(float64(diff)))
		i++
	}

	if len(latencies) == 0 {
		return "\nNo info\n"
	}

	var jitter time.Duration
	if i > 1 {
		jitter = time.Duration(totalDiff.Nanoseconds() / (int64(i) - 1))
	}
	avgDelay := time.Duration(totalDelay.Nanoseconds() / (int64(i)))
	packetLoss := strings.Split(regexp.MustCompile(`\d+% packet loss`).FindString(string(raw)), "%")[0]

	return fmt.Sprintf("\n\tJitter:\t\t\t%s\n\tAverage latency:\t%s\n\tPacket loss:\t\t%s\n", jitter, avgDelay, packetLoss)
}

// nolint: gocyclo
func processBandwidthFiles(fileName string) string {
	//#nosec
	raw, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Error("Reading bandwidth file", "file", fileName, "err", err)
		return ""
	}

	// Trim the Ctrl and non ascii characters from the
	trimmed := trimJunk(string(raw))

	type bandwidthStats struct {
		lossServerToClient float64
		lossClientToServer float64
		bwServerToClient   uint64
		bwClientToServer   uint64
	}

	// To calculate avg loss then you need to know the actual number of lost packets from the packet size and count
	// params
	totalAchievedCSBW := uint64(0)
	totalAchievedSCBW := uint64(0)
	totalAttemptedCSBW := uint64(0)
	totalAttemptedSCBW := uint64(0)

	var bandwidthMeasurements []bandwidthStats
	for _, block := range strings.Split(trimmed, strings.Repeat("#", 10)+"\n") {
		// Check the path to make sure we used that link and not some other path
		path := regexp.MustCompile(`path=".*"`).FindString(block)
		path = regexp.MustCompile(pathRegex).FindString(path)
		hops := strings.Split(path, ">")
		if len(hops) != 2 {
			continue
		}

		// Get the C->S stats
		re := regexp.MustCompile(`(?m)C->S results\n((?:.*\n){5})`)
		cToS := re.FindString(block)
		if strings.TrimSpace(cToS) == "" { // The bwtest failed for some reason
			//fmt.Println("Client to server connection failed")
			//errStr := regexp.MustCompile(`lvl=(eror|crit) msg=.+`).FindAllString(block, -1)
			//fmt.Println(errStr)
			continue
		}

		achievedBW, attemptedBW, loss, err := getBandwidthInfoFromBlock(cToS)
		if err != nil {
			log.Error("Parsing info from bandwidth client to server data block", "err", err)
			continue
		}

		totalAchievedCSBW += achievedBW
		totalAttemptedCSBW += attemptedBW
		measurement := bandwidthStats{
			bwClientToServer:   achievedBW,
			lossClientToServer: loss,
		}

		// Get the S->C stats
		re = regexp.MustCompile(`(?m)(S->C results\n((?:.*\n){5}))`)
		sToC := re.FindString(block)
		if strings.TrimSpace(sToC) == "" {
			//fmt.Println("Server to client connection failed")
			//errStr := regexp.MustCompile(`lvl=(eror|crit) msg=.+`).FindAllString(block, -1)
			//fmt.Println(errStr)
			continue
		}
		achievedBW, attemptedBW, loss, err = getBandwidthInfoFromBlock(sToC)
		if err != nil {
			log.Error("Parsing info from bandwidth server to client data block", "err", err)
			continue
		}

		totalAchievedSCBW += achievedBW
		totalAttemptedSCBW += attemptedBW
		measurement.bwServerToClient = achievedBW
		measurement.lossServerToClient = loss

		// Append the new info to our info slice
		bandwidthMeasurements = append(bandwidthMeasurements, measurement)
	}

	if len(bandwidthMeasurements) == 0 {
		return "\nNo info\n"
	}
	avgCSBw := totalAchievedCSBW / uint64(len(bandwidthMeasurements))
	avgSCBw := totalAchievedSCBW / uint64(len(bandwidthMeasurements))

	var avgCSLoss float64
	var avgSCLoss float64
	if totalAttemptedCSBW != 0 && totalAttemptedSCBW != 0 {
		avgCSLoss = 1 - (float64(totalAchievedCSBW) / float64(totalAttemptedCSBW))
		avgSCLoss = 1 - (float64(totalAchievedSCBW) / float64(totalAttemptedSCBW))
	}

	return fmt.Sprintf("\nClient -> Server stats:\n\tAverage available bandwidth:	%f Mbps"+
		"\n\tAverage loss:			%f%%\nServer -> Client stats:\n\tAverage available bandwidth:	%f Mbps"+
		"\n\tAverage loss:			%f%%\nTotal Measurements:	%d\nFailed Measurements:	%d\n",
		float64(avgCSBw)/1000000, avgCSLoss*100, float64(avgSCBw)/1000000, avgSCLoss*100,
		len(strings.Split(trimmed, strings.Repeat("#", 10)+"\n"))-1,
		len(strings.Split(trimmed, strings.Repeat("#", 10)+"\n"))-len(bandwidthMeasurements)-1)
}

// getBandwidthInfoFromBlock processes a Bandwidth data block and returns the achieved bandwidth, attempted bandwidth,
// and loss in that block
func getBandwidthInfoFromBlock(block string) (uint64, uint64, float64, error) {
	achievedBWStr := regexp.MustCompile(`(Achieved bandwidth: \d+)`).FindString(block)
	// Convert rate uint64 to represent in bps
	achievedBW, err := strconv.ParseUint(strings.TrimSpace(strings.Split(achievedBWStr, ":")[1]), 10, 64)
	if err != nil {
		return 0, 0, 0, common.NewBasicError("Parsing Uint for bandwidth", err)
	}
	// get the attempted bandwidth as well to calculate the avg loss at the end
	attemptedBWStr := regexp.MustCompile(`(Attempted bandwidth: \d+)`).FindString(block)
	// Convert rate uint64 to represent in bps
	attemptedBW, err := strconv.ParseUint(strings.TrimSpace(strings.Split(attemptedBWStr, ":")[1]), 10, 64)
	if err != nil {
		return 0, 0, 0, common.NewBasicError("Parsing Uint for bandwidth", err)
	}
	// PacketLoss
	lossStr := strings.Split(regexp.MustCompile(`Loss rate: \d+`).FindString(block), ":")[1]
	loss, err := strconv.ParseFloat(strings.TrimSpace(lossStr), 64)
	if err != nil {
		return 0, 0, 0, common.NewBasicError("Parsing float for loss", err)
	}

	return achievedBW, attemptedBW, loss, nil

}

// trimJunk trims all non ASCII chars uses trimCtrlChars to trim unwanted control characters
func trimJunk(s string) string {
	// Get only ASCII chars
	re := regexp.MustCompile("[[:^ascii:]]")
	ascii := re.ReplaceAllLiteralString(s, "")
	trimmed := trimCtrlChars(ascii)
	return trimmed
}

// trimCtrlChars trims all unnecessary control characters in str
func trimCtrlChars(str string) string {
	b := make([]byte, len(str))
	var bl int
	for i := 0; i < len(str); i++ {
		c := str[i]
		if c >= 32 && c != 127 || c == 10 || c == 13 || c == 230 { // 230=mu, 10=\n, 13=\r
			b[bl] = c
			bl++
		}
	}
	return string(b[:bl])
}
