# Dynamic Links: An Experimentation Automation Tool for SCION
## Description 
Dynamic Links is an experimentation automation tool for SCION.
It allows its users to selectivly fail and/or deteriorate links on local containerized topology which is connected to SCIONLab.

It deploys a containerized SCION topology in the user's machine that is connected to SCIONLab using the `topo` subcommand.
Then the user is able to modify any of the links in the topology by using the `exp` subcommand.
It provides different link deterioration and revocation options (described in detail in [Properties]()). 

It uses the SCION [docker script](https://github.com/scionproto/scion/tree/master/docker) to deploy the containerized topology.
 
## Requirements
1. At the least a SCION AS running on the host machine, steps for installing SCION can be found [here](https://netsec-ethz.github.io/scion-tutorials/). 
The tool can be ran on a physical machine or on the SCION VM.

2. The [SCION apps](https://github.com/netsec-ethz/scion-apps/blob/master/README.md) should be installed on the host machine (especially the bwtester application). 

2. [tcconfig](https://github.com/thombashi/tcconfig): can be installed using pip or by using the script [deps.sh](deps.sh). It provides a wrapper for the `tc` utility on linux, and allows easy control of interfaces or docker containers.

3. [Docker](https://docs.docker.com/).

4. User needs to be able to run `sudo` command to be able to use the full functionality of the tool (needed mainly for modifying the links with `tc`)

All the dependencies can be installed by running the [deps.sh](deps.sh) script. 

## Usage
The tool has two main modes of operation:
- Topology creation with the `topo` subcommand.
- Running link modification experiments using the `exp` subcommand.

### Topology Creation 
The tool can be used to create a new topology by running the following command (assuming the tool is built as dynlinks):
```bash
./dynlinks -config TOPO.YAML -buildApps -o EMPTY_PROPERTIES.YAML
```
The `-config` option is used to specify the topology configuration to use, the configuration follows the same structure as [SCION's local topology files](https://github.com/scionproto/scion/tree/master/topology).
An example with comments can be seen in the [example.topo](example.topo) file.
 The `-buildApps` flag is used to tell the tool to build the SCION apps inside the containers.
`-o` tells the tool to output an empty links properties file after creating the topology so it can be used later to modify links. 

### Modifying links
The user can set the properties of links in the topology interactively by running using the `-i` flag:
```bash
./dynlinks exp -gen PATH/TO/GEN/DIRS -i
```
The `-gen` option is to pass to the tool the location where the gen directories mounted by the containers are mounted (more information in the [example.topo](example.topo) file). 

To run the tool using a properties file:
```bash
./dynlinks exp -gen PATH/TO/GEN/DIRS -p PROPERTIES.YAML
```
The properties can be obtained by running the tool with the `-o` option.

For more ifrmation about the different options, use the `-h` or `-help` flag with any of the tools sub commands.
 
 
 
## Internals
### Links
<!--configuration files-->
Dynamic Links needs to be pointed to th directory where the gen directories of the running SCION docker containers are. From there it can load the proper configuration files (AS IA, keys, and topology). As for the SCION instance running on the host machine, the tool will navigate to the ```$SC/gen``` directory to find the configuration files for that AS. The tool would then determine the links between the docker containers and host AS based on the topology.json file of each AS. Then it constructs a structure to hold each one of the found links.

A single link has the following structure:
```go
type Link struct {
	ASA     string
	IFA     common.IFIDType
	ASB     string
	IFB     common.IFIDType
	Type    proto.LinkType
	Properties LinkProperties
}
```
- `ASA` is the one of the two ASes IA
- `IFA` is the IFID for `ASA`
- `ASB` is the second AS in the link
- `IFB` is the IFID for `ASB`
- `Type` is the type of link from `ASA` point of view
- `Properties` are the metrics to be applied on that link


#### Properties ####
Each one of the links has metrics to be applied to it. The tool's 
structure for the metrics is: 
```go
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
```
The metrics represent the following: 
- Rate: the available bandwidth on the link. Maximum value is 10Mbps, minimum value is 8bps (`tcconfig` limitation).
- Delay: the latency to add to add to the packets on the link.
- Delay distribution : the higher the value of this option the higher the jitter on that link would be. This is used only if the delay parameter is set. If this parameters is set, then the delay on the link would follow a normal distribution distribution of network latency becomes X +- \[0, Y\] (normal distribution), here X is the value of "delay" option and Y is the value of "delay-dist". Network latency distribution is uniform without this option.
- Loss: the percentage of packet loss on the link.
- Duplicate: the probability that a packet would be duplicated on the link.
- Reorder: needs to be set with the delay option, the percentage here represents the percentage of packets which would be sent immediately with no delay. For example, let's assume a delay of 10ms and reorder is set to 25%, then 25% of packets are sent immediately while the others are delayed by 10 ms.
- Corrupt: the probability of having a single bit error at a random offset in the packet.
- Revoke: if set to true, the interface will be revoked.
- Revocation method: the method to use for the link (or interface) revocation. It can be topo (to remove interface from the border router topology), token (send ifState Update continuously to the border routers and path servers with signed revocation info), block (blocks all SCION packets incoming or outgoing from the interface using tcconfig). 
- Revocation Period: the period to keep an interface revoked. This would make and interface revoked for one period then back up for the second period, resulting in a "blinking" interface. The default is the revocation is continuous.
- Revocation Probability: the probability that an interface would be revoked, or revoked in a given period if the revocation period is set.

### Modifying the links
Then it applies the link metrics to the specified links by running multiple instances of the [modiface](modiface) module. The modiface package is used to modify one interface in the topology. 

The interface that is modified in a link is the child link. For example if we modify a link between **AS A** and **AS B**, with **A** being the parent and **B** is the child AS, then the interface in **A** would be altered. Because if the interface is modified from **B**'s side then we risk losing communication with the AS which results in errors if we are communicating with the services in that AS.
 
 The tools has three modes of operation: 
1. **Interactive**: the user is prompted to modify each one of the found links, and then prompted to save the new links metrics into a YAML file for later use.
2. **Output**: outputs a sample metrics file (with the default metrics). 
3. **Load properties file**: loads the specified metrics file and applies  it to the available links.


### Logging
The [collector](collector/collector.go) module collects raw logs for each one of the links, it uses the following tools:
1. [scmp](https://github.com/scionproto/scion/tree/master/go/tools/scmp) to measure the latency (RTT).
2. [bwtester](https://github.com/netsec-ethz/scion-apps/tree/master/bwtester) to measure the bandwidth on each link.
3. [showpaths](https://github.com/scionproto/scion/tree/master/go/tools/showpaths) to retrieve paths to all the available ASes.
4. [ps](http://man7.org/linux/man-pages/man1/ps.1.html) and [docker stats](https://docs.docker.com/engine/reference/commandline/stats/) to monitor the resource usage of the SCION processes.

Each output of the mentioned tools would be logged to a separate file, and used later for further analysis by the aggregator function.
The aggregation aggregates some of the data from the collector and shows them to the user, more work is to be done on the aggregator.



### More details to be added later on
