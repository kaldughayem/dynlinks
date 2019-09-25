package conf

import (
	"fmt"
	"time"
)

// LinkProperties are the metrics to be applied to a link and is used by the modiface
// and collector modules.
type LinkProperties struct {
	Rate             string
	Delay            time.Duration
	DelayDist        time.Duration
	Loss             float64
	Duplicate        float64
	Reorder          float64
	Corrupt          float64
	Revoke           bool
	RevocationMethod string
	RevocationPeriod time.Duration
	RevocationProb   float64
}

// Print all the metrics and their values
func (m *LinkProperties) Print() {
	fmt.Println("Properties: ")
	fmt.Printf("\tDelay: \t\t\t\t%s\n", m.Delay.String())
	fmt.Printf("\tDelay distribution: \t\t%s\n", m.DelayDist.String())
	fmt.Printf("\tRate: \t\t\t\t%s\n", m.Rate)
	fmt.Printf("\tLoss: \t\t\t\t%f%%\n", m.Loss)
	fmt.Printf("\tDuplication: \t\t\t%f%%\n", m.Duplicate)
	fmt.Printf("\tReordering: \t\t\t%f%%\n", m.Reorder)
	fmt.Printf("\tCorrupt: \t\t\t%f%%\n", m.Corrupt)
	fmt.Printf("\tRevoke Link: \t\t\t%t\n", m.Revoke)
	fmt.Printf("\tRvocation method: \t\t%s\n", m.RevocationMethod)
	fmt.Printf("\tRvocation period: \t\t%s\n", m.RevocationPeriod)
	fmt.Printf("\tRevcoation probability: \t%f%%\n", m.RevocationProb)
}

// DefaultProperties is the default values for all the metrics fields
func DefaultProperties() LinkProperties {
	return LinkProperties{
		Rate:             "",
		Delay:            0,
		DelayDist:        0,
		Loss:             0,
		Duplicate:        0,
		Reorder:          0,
		Corrupt:          0,
		Revoke:           false,
		RevocationMethod: "",
		RevocationPeriod: 0,
		RevocationProb:   100,
	}
}
