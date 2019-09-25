package ui

import (
	"bufio"
	"fmt"
	"github.com/kaldughayem/dynlinks/conf"
	"github.com/kaldughayem/dynlinks/utils"
	"github.com/scionproto/scion/go/lib/log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// HandleInteractive handles the interactive mode.
func HandleInteractive(links conf.Links) {

	// Used to be displayed to the user and so the user is able to choose index of the link when in
	// interactive mode
	dispLinks := make([]string, 0)
	for id := range links {
		dispLinks = append(dispLinks, id)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		// Print links to show to user
		for i, id := range dispLinks {
			fmt.Printf("[%d] Links experimentID: %s\n", i, id)
		}
		// 1- prompt the user to choose link, if user types "done" then break from the loop and run the
		// modiface tool
		fmt.Println("Choose a link, and enter \"done\" when finished and want to run the tool")
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Error("Reading user input", "err", err)
		}
		input = strings.TrimSpace(input)

		if input == "done" {
			fmt.Println("link modification finished")
			break
		}

		if input == "help" {
			fmt.Println("Please choose one of the displayed links to modify based on their index 0-",
				len(links))
			continue
		}

		choice, err := strconv.Atoi(input)
		if err != nil {
			log.Error("Error parsing user input to int", "err", err)
			continue
		}
		if choice > len(links)-1 || choice < 0 {
			log.Error("Invalid link index")
			continue
		}

		// Get the chosen link and set as the active one to modify
		fmt.Println("Chosen link: ", dispLinks[choice])
		handleLink(reader, links[dispLinks[choice]])
	}

	promptSaveProperties(links)
}

func promptSaveProperties(links conf.Links) {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("save properties file? [y, n]")
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Error("Reading user input", "err", err)
		}
		input = strings.TrimSpace(input)
		if input == "y" {
			fmt.Println("Enter filename")
			input, err = reader.ReadString('\n')
			if err != nil {
				log.Error("Reading user input", "err", err)
			}
			input = strings.TrimSpace(input)
			// Save the links map to YAML file
			if err := utils.SaveToYAMLFile(input, &links); err != nil {
				log.Error("Saving to file", "err", err)
				continue
			}

			break
		}
		if input == "n" {
			break
		}
	}
}

func handleLink(reader *bufio.Reader, activeLink *conf.Link) {
	for {
		// 2- prompt for options to apply to that activeLink (can select multiple ones), if user types "done"
		// then go back to step 1
		fmt.Println("Choose properties for the activeLink: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Error("Reading user input", "err", err)
		}
		input = strings.TrimSpace(input)

		if input == "done" {
			if err = utils.ValidateProperties(&activeLink.Properties); err != nil {
				log.Error("Validating properties,", "err", err)
				fmt.Println("Please re-enter properties for the activeLink")
				continue
			} else {
				fmt.Println("Finished modifying Link: ", activeLink.ASA, activeLink.ASB)
				activeLink.Properties.Print()
				break
			}
		} else if input == "show" {
			activeLink.Properties.Print()
			continue
		} else if input == "help" {
			printHelp()
			fmt.Println("Example input: delay=300ms,delay-dist=150ms,rate=100Kbps")
			fmt.Println(" This will set the delay and rate on that activeLink, while the other parameters" +
				" will be set to their defaults (e.g. loss=0 and revoke=false). \n " +
				"Enter \"printHelp\" to see printHelp for properties, \"show\" to show the current properties for the activeLink " +
				"or \"done\" when finished modifying this interface")
			continue
		}

		processParams(input, activeLink)

	}
}

// processParams processes user entered values for properties interactively.
func processParams(input string, activeLink *conf.Link) {
	// User entered parameters should be separated by a comma
	params := strings.Split(input, ",")
	if len(params) < 1 {
		log.Error("Invalid Input", "input", input)
	}

	for _, param := range params {
		p := strings.Split(param, "=")
		if len(p) <= 1 {
			log.Error("Invalid (key=value) pair entered", "Input", p)
			continue
		}
		p[0] = strings.TrimSpace(p[0])
		p[1] = strings.TrimSpace(p[1])
		switch p[0] {
		case "delay":
			d, err := time.ParseDuration(p[1])
			if err != nil {
				log.Error("Unrecognized value for the delay", "value", p[1], "err", err)
				fmt.Println("Delay to add to that link [duration] valid range 0s-60m. Units " +
					"[us]=microseconds, [ms]=milliseconds, [s]=seconds, [m]=minutes, [h]=hours")
				break
			}
			activeLink.Properties.Delay = d

		case "delay-dist":
			d, err := time.ParseDuration(p[1])
			if err != nil {
				log.Error("Unrecognized value for the delay distribution", "value", d)
				fmt.Println("Delay dist [duration] valid range 0s-60m. Units " +
					"[us]=microseconds, [ms]=milliseconds, [s]=seconds, [m]=minutes, [h]=hours")
				break
			}

			activeLink.Properties.DelayDist = d

		case "rate":
			if p[1] == "" {
				break
			}
			re := regexp.MustCompile("^[0-9]+([MmGgTtKk]?(bps|bit/s))$")
			value := re.FindAllString(p[1], -1)
			if len(value) != 1 {
				log.Error("Parsing rate value", "value", p[1])
				fmt.Println("Bandwidth rate for the link. Minimum is 8bps, available-units=[tT]bps," +
					" [tT]bit/s, [gG]bps, [gG]bit/s, bps, bit/s, [kK]bps, [kK]bit/s, [mM]bps, [mM]bit/s," +
					" [kK]ibps, [kK]ibit/s, [mM]ibps, [mM]ibit/s, [tT]ibps, [tT]ibit/s, [gG]ibps, " +
					"[gG]ibit/s")
				break
			}
			activeLink.Properties.Rate = p[1]

		case "loss":
			v, err := strconv.ParseFloat(p[1], 64)
			if err != nil || v > 100 || v < 0 {
				log.Error("Loss rate value parsing failed", "value", p[1])
				println("Loss [%] valid range from 0-100")
				break
			}
			activeLink.Properties.Loss = v

		case "duplicate":
			v, err := strconv.ParseFloat(p[1], 64)
			if err != nil || v > 100 || v < 0 {
				log.Error("Duplication probability value parsing failed", "value", p[1])
				println("Duplication probability [%] valid range from 0-100")
				break
			}
			activeLink.Properties.Duplicate = v

		case "reorder":
			v, err := strconv.ParseFloat(p[1], 64)
			if err != nil || v > 100 || v < 0 {
				log.Error("Reordering rate value parsing failed", "value", p[1])
				println("Reordering probability [%] valid range from 0-100 (must be set with delay)")
				break
			}
			activeLink.Properties.Reorder = v

		case "corrupt":
			v, err := strconv.ParseFloat(p[1], 64)
			if err != nil || v > 100 || v < 0 {
				log.Error("Corruption probability value parsing failed", "value", p[1])
				println("Corruption probability [%] valid range from 0-100")
				break
			}
			activeLink.Properties.Corrupt = v

		case "revoke":
			v, err := strconv.ParseBool(p[1])
			if err != nil {
				log.Error("Revocation flag value parsing failed", "value", p[1])
				println("Revoke link [bool] valid values [true, false]")
				break
			}
			activeLink.Properties.Revoke = v

		case "rev-method":
			re := regexp.MustCompile("^(?i)(topo|block|token)$")
			value := re.FindAllString(p[1], -1)
			if len(value) != 1 {
				log.Error("Parsing revocation method", "value", p[1])
				println("Revocation method valid values: topo (to remove interface from " +
					"the border router topology), token (send ifState Update continuously to the border " +
					"routers and path servers with signed revocation info), block (blocks all SCION " +
					"packets incoming or outgoing from the interface using tcconfig)")
				break
			}
			activeLink.Properties.RevocationMethod = p[1]

		case "rev-period":
			d, err := time.ParseDuration(p[1])
			if err != nil {
				log.Error("Revocation period value parsing failed", "value", p[1])
				fmt.Println("Revocation period [duration] valid range 0s-60m. Units " +
					"[us]=microseconds, [ms]=milliseconds, [s]=seconds, [m]=minutes, [h]=hours")
				break
			}
			activeLink.Properties.RevocationPeriod = d

		case "rev-prob":
			v, err := strconv.ParseFloat(p[1], 64)
			if err != nil || v > 100 || v < 0 {
				log.Error("Revocation probability value parsing failed", "value", p[1])
				fmt.Println("Revocation probability [%] valid range from 0-100")
				break
			}
			activeLink.Properties.Corrupt = v
		default:
			log.Error("Unrecognized parameter name", "param", p[0])
			fmt.Println("Example input: delay=300ms,delay-dist=150ms,rate=100Kbps")
			fmt.Println(" This will set the delay and rate on that link, while the other parameters" +
				" will be set to their defaults (e.g. loss=0 and revoke=false). \n " +
				"Enter \"printHelp\" to see printHelp for properties, \"show\" to show the current properties for the " +
				"link or \"done\" when finished modifying this interface")
		}
	}
}

func printHelp() {
	rate := "Bandwidth rate for the link. Minimum is 8bps, available-units=[tT]bps, [tT]bit/s, [gG]bps, [gG]bit/s, " +
		"bps, bit/s, [kK]bps, [kK]bit/s, [mM]bps, [mM]bit/s"
	delay := "Delay to add to the link valid range 0s-60m. Valid units [us]=microseconds, [ms]=milliseconds, " +
		"[s]=seconds, [m]=minutes, [h]=hours"
	delayDist := "distribution of network latency becomes X +- Y (normal distribution). Here X is the value of " +
		"\"delay\" option and Y is the value of \"delay-dist\" option). Network latency distribution is uniform " +
		"without this option. Units [none]=milliseconds, [us]=microseconds, [ms]=milliseconds, [s]=seconds, " +
		"[m]=minutes, [h]=hours. This option must be used with the delay option."
	loss := "Packet loss rate [%]. The valid range is from 0 to 100. (default=0)"
	duplicate := "Packet duplication rate [%]. Valid range from 0 to 100. (default=0)"
	reorder := "Packet reordering rate [%]. Valid range from 0 to 100. (default=0)"
	corrupt := "packet corruption rate [%]. Valid range from 0 to 100. packet corruption means single bit error at" +
		" a random offset in the packet. (default=0)"
	revoke := "Revoke the specific interface/link. All other link options will be ignored when this flag is set"
	revocationMethod := "Revocation method valid values: topo (to remove interface from " +
		"the border router topology), token (send ifState Update continuously to the border " +
		"routers and path servers with signed revocation info), block (blocks all SCION " +
		"packets incoming or outgoing from the interface using tcconfig). (default=topo)"
	revocationPeriod := "Delay between interface revocations. Units [us]=microseconds, [ms]=milliseconds, " +
		"[s]=seconds, [m]=minutes, [h]=hours. (default=1s)"
	revocationProb := "probability of revoking an interface during a single period [%]. A period length is " +
		"determined by the previous option 'rev-period'. Valid range 0 to 100."

	fmt.Printf("- Rate (rate=BANDWIDTH_RATE): \n\t%s\n", rate)
	fmt.Printf("- Delay (delay=TIME_DURATION): \n\t%s\n", delay)
	fmt.Printf("- Delay distribution (delay-dist=TIME_DURATION: \n\t%s\n", delayDist)
	fmt.Printf("- Loss rate (loss=LOSS_RATE): \n\t%s\n", loss)
	fmt.Printf("- Duplication rate (duplicate=DUPLICATION_RATE): \n\t%s\n", duplicate)
	fmt.Printf("- Corruption rate (corrupt=CORRUPTION_RATE): \n\t%s\n", corrupt)
	fmt.Printf("- Reordering rate (reorder=REORDER_RATE): \n\t%s\n", reorder)
	fmt.Printf("- Revoke (revoke=BOOL): \n\t%s\n", revoke)
	fmt.Printf("- Revocation method (rev-method=token|topo|block): \n\t%s\n", revocationMethod)
	fmt.Printf("- Revocation period (rev-period=TIME_DURATION): \n\t%s\n", revocationPeriod)
	fmt.Printf("- Revocation probability (rev-prob=PROBABILITY): \n\t%s\n", revocationProb)
}
