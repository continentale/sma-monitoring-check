/**
 * @package   sma-monitoring-check
 * @copyright sma-monitoring-check contributors
 * @license   GNU Affero General Public License (https://www.gnu.org/licenses/agpl-3.0.de.html)
 *
 * @todo lots of documentation
 *
 *
 * this check is the counterpart of the sma-monitoring-agent. With this check you can monitor the agent endpoints
 */

package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type win32 struct {
	win32LogicalDisk     []win32LogicalDisk
	win32Process         []win32Process
	win32Processor       []win32Processor
	win32Service         []win32Service
	win32OperatingSystem []win32OperatingSystem
	inventory            inventory
	multiCoreCPU         MultiCPUCores
	command              CustomCommand
	version              AgentVersion
}
type CustomCommand struct {
	Output   string
	ExitCode string
}
type AgentVersion struct {
	Version   string
	BuildTime string
	GitHash   string
}

type win32LogicalDisk struct {
	Name      string
	FreeSpace string
	Size      string
}

type win32Process struct {
	Name         string
	Caption      string
	Shellcommand string `json:"commandline"`
}

type win32Processor struct {
	LoadPercentage int64
	Name           string
}
type win32Service struct {
	Caption string
	Name    string
	State   string
}
type win32OperatingSystem struct {
	TotalVisibleMemorySize int64
	FreePhysicalMemory     int64
	TotalVirtualMemorySize int64
	FreeVirtualMemory      int64
}

type inventory struct {
	Model                     string
	Manufacturer              string
	Name                      string
	Domain                    string
	NumberOfProcessors        int64
	NumberOfLogicalProcessors int64
	TotalPhysicalMemory       int64
	IdentifyingNumber         string
}

type MultiCPUCores struct {
	CPUType []CPUType `json:"CPUType"`
	Usage   []float64 `json:"Usage"`
}
type CPUType struct {
	CPU        int           `json:"cpu"`
	VendorID   string        `json:"vendorId"`
	Family     string        `json:"family"`
	Model      string        `json:"model"`
	Stepping   int           `json:"stepping"`
	PhysicalID string        `json:"physicalId"`
	CoreID     string        `json:"coreId"`
	Cores      int           `json:"cores"`
	ModelName  string        `json:"modelName"`
	Mhz        int           `json:"mhz"`
	CacheSize  int           `json:"cacheSize"`
	Flags      []interface{} `json:"flags"`
	Microcode  string        `json:"microcode"`
}

type apiRequest struct {
	host           string
	port           int64
	types          string
	availableTypes map[string]string
	warning        string
	critical       string
	win32          win32
	param          string
	paramshell     string
	secret         string
	secure         bool
}

//var MySingingKey byte

func (api *apiRequest) doCurl() (*http.Response, error) {

	client := http.Client{
		Transport: &http.Transport{
			Proxy:           nil,
			TLSClientConfig: &tls.Config{},
		},
		Timeout: time.Duration(20) * time.Second,
	}

	protokol := "http"
	if api.secure {
		protokol = "https"
	}

	params := ""
	commandLine := ""

	if api.param != "" {
		params = "?name=" + api.param
		params = strings.ReplaceAll(api.param, " ", "%20")

	}
	if api.paramshell != "" {
		commandLine = "&commandLine=" + api.paramshell
	}
	req, _ := http.NewRequest("GET", protokol+"://"+api.host+":"+strconv.FormatInt(api.port, 10)+api.availableTypes[api.types]+params+commandLine, nil)

	req.Header.Set("Token", api.secret)
	return client.Do(req)

}

func (api *apiRequest) parseDataTo(resp *http.Response) {
	data, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		status["code"] = "3"
		status["status"] = "UNKNOWN"
		status["message"] = "Check is running on a problem: " + err.Error()
	}

	switch api.types {
	case "multicpu":
		json.Unmarshal(data, &api.win32.multiCoreCPU)
	case "cpu":
		json.Unmarshal(data, &api.win32.win32Processor)
	case "memory":
		json.Unmarshal(data, &api.win32.win32OperatingSystem)
	case "disk":
		json.Unmarshal(data, &api.win32.win32LogicalDisk)
	case "service":
		json.Unmarshal(data, &api.win32.win32Service)
	case "process":
		json.Unmarshal(data, &api.win32.win32Process)
	case "inventory":
		json.Unmarshal(data, &api.win32.inventory)
	case "command":
		json.Unmarshal(data, &api.win32.command)
	case "version":
		json.Unmarshal(data, &api.win32.version)
	}

	if err != nil {
		status["code"] = "3"
		status["status"] = "UNKNOWN"
		status["message"] = "Check is running on a problem: " + err.Error()
	}
}

func (api *apiRequest) checkStatus() {

	switch api.types {
	case "multicpu":
		status["message"] = "CPU Load ("
		status["code"] = "0"
		status["status"] = "OK"

		for i := range api.win32.multiCoreCPU.Usage {
			loadPercentage := api.win32.multiCoreCPU.Usage[i]
			loadPercentageString := strconv.FormatFloat(loadPercentage, 'f', 2, 64)

			if i > 0 {
				status["message"] = status["message"] + " -  "
			}
			status["message"] = status["message"] + loadPercentageString + "%"
			status["perfData"] = status["perfData"] + "load" + fmt.Sprint(i) + "=" + loadPercentageString + ";" + api.warning + ";" + api.critical + ";; "

			if critical, _ := strconv.ParseFloat(api.critical, 64); critical < loadPercentage && status["code"] < "2" {
				status["code"] = "2"
				status["status"] = "CRITICAL"

			}
			if warning, _ := strconv.ParseFloat(api.warning, 64); warning < loadPercentage && status["code"] < "1" {
				status["code"] = "1"
				status["status"] = "WARNING"
			}
		}
		status["message"] = status["message"] + ")"

	case "cpu":
		for i := range api.win32.win32Processor {
			loadPercentage := api.win32.win32Processor[i].LoadPercentage
			loadPercentageString := strconv.FormatInt(loadPercentage, 10)
			status["message"] = "CPU Load: "
			if critical, _ := strconv.ParseInt(api.critical, 10, 0); critical < loadPercentage {
				status["code"] = "2"
				status["status"] = "CRITICAL"
				status["message"] = "CRITICAL:  CPU load " + loadPercentageString + "%"
				status["perfData"] = "load=" + loadPercentageString + ";" + api.warning + ";" + api.critical + ";; "
			} else if warning, _ := strconv.ParseInt(api.warning, 10, 0); warning < loadPercentage {
				status["code"] = "1"
				status["status"] = "WARNING"
				status["message"] = "WARNING: CPU load " + loadPercentageString + "%"
				status["perfData"] = "load=" + loadPercentageString + ";" + api.warning + ";" + api.critical + ";; "
			} else {
				status["code"] = "0"
				status["status"] = "OK"
				status["message"] = "OK: CPU load " + loadPercentageString + "%"
				status["perfData"] = "load=" + loadPercentageString + ";" + api.warning + ";" + api.critical + ";; "
			}
		}
		status["message"] = status["message"] + ""

	case "memory":
		for i := range api.win32.win32OperatingSystem {
			memoryPercentage := int64((float32(api.win32.win32OperatingSystem[i].FreePhysicalMemory) / float32(api.win32.win32OperatingSystem[i].TotalVisibleMemorySize)) * 100.0)
			memoryPercentage = 100 - memoryPercentage
			memoryTotal := api.win32.win32OperatingSystem[i].TotalVisibleMemorySize / 1024
			memoryFree := api.win32.win32OperatingSystem[i].FreePhysicalMemory / 1024
			memoryTotalString := fmt.Sprintf("%d", memoryTotal)
			memoryFreeString := fmt.Sprintf("%d", memoryFree)
			memoryUsedString := fmt.Sprintf("%d", (memoryTotal - memoryFree))
			memoryPercentageString := fmt.Sprintf("%d", memoryPercentage)

			if critical, _ := strconv.ParseInt(api.critical, 10, 0); critical < memoryPercentage {
				status["code"] = "2"
				status["status"] = "CRITICAL"
				status["message"] = "CRITICAL: Memory usage: " + memoryPercentageString + "% (Total: " + memoryTotalString + " MB - Free: " + memoryFreeString + " MB - Used: " + memoryUsedString + " MB)"
				status["perfData"] = "memory=" + memoryPercentageString + ";" + api.warning + ";" + api.critical + ";; "
			} else if warning, _ := strconv.ParseInt(api.warning, 10, 0); warning < memoryPercentage {
				status["code"] = "1"
				status["status"] = "WARNING"
				status["message"] = "WARNING: Memory usage: " + memoryPercentageString + "% (Total: " + memoryTotalString + " MB - Free: " + memoryFreeString + " MB - Used: " + memoryUsedString + " MB)"
				status["perfData"] = "memory=" + memoryPercentageString + ";" + api.warning + ";" + api.critical + ";; "
			} else {
				status["code"] = "0"
				status["status"] = "OK"
				status["message"] = "OK: Memory usage: " + memoryPercentageString + "% (Total: " + memoryTotalString + " MB - Free: " + memoryFreeString + " MB - Used: " + memoryUsedString + " MB)"
				status["perfData"] = "memory=" + memoryPercentageString + ";" + api.warning + ";" + api.critical + ";; "
			}
		}

	case "disk":
		status["message"] = "Disk usage: "
		status["code"] = "0"
		status["status"] = "OK"

		for i := range api.win32.win32LogicalDisk {
			if strings.Contains(api.critical, "G") || strings.Contains(api.warning, "G") {
				//critical is a non procentual value
				freespace, _ := strconv.ParseFloat(api.win32.win32LogicalDisk[i].FreeSpace, 32)
				freeSpaceInGB := freespace / 1024 / 1024 / 1024
				size, _ := strconv.ParseFloat(api.win32.win32LogicalDisk[i].Size, 64)
				size = size / 1024 / 1024 / 1024
				freespace = freespace / 1024 / 1024 / 1024

				if i > 0 {
					status["message"] = status["message"] + " - "
				}

				status["message"] = status["message"] + "" + api.win32.win32LogicalDisk[i].Name + "\\ " + fmt.Sprintf("%.2f", freeSpaceInGB) + "% (Total: " + fmt.Sprintf("%.2f", size) + " GB - Free: " + fmt.Sprintf("%.2f", freespace) + "GB)"
				status["perfData"] = status["perfData"] + api.win32.win32LogicalDisk[i].Name + "=" + fmt.Sprintf("%.2f", freeSpaceInGB) + ";" + api.warning[:len(api.warning)-1] + ";" + api.critical[:len(api.critical)-1] + ";; "
				if critical, _ := strconv.ParseFloat(api.critical[0:len(api.critical)-1], 64); critical > freeSpaceInGB && status["code"] < "2" {
					status["code"] = "2"
					status["status"] = "CRITICAL"

				}
				if warning, _ := strconv.ParseFloat(api.warning[0:len(api.warning)-1], 64); warning > freeSpaceInGB && status["code"] < "1" {
					status["code"] = "1"
					status["status"] = "WARNING"
				}

			} else {
				freespace, _ := strconv.ParseFloat(api.win32.win32LogicalDisk[i].FreeSpace, 32)
				size, _ := strconv.ParseFloat(api.win32.win32LogicalDisk[i].Size, 32)
				sizetmp, _ := strconv.ParseFloat(api.win32.win32LogicalDisk[i].Size, 64)
				freetmp, _ := strconv.ParseFloat(api.win32.win32LogicalDisk[i].FreeSpace, 64)
				sizetmp = sizetmp / 1024 / 1024 / 1024
				freetmp = freetmp / 1024 / 1024 / 1024
				usage := int64((freespace / size) * 100)
				usage = 100 - usage
				usageString := fmt.Sprintf("%d", usage)
				sizeString := fmt.Sprintf("%.2f", sizetmp)
				freeString := fmt.Sprintf("%.2f", freetmp)

				if i > 0 {
					status["message"] = status["message"] + " - "
				}

				status["message"] = status["message"] + "" + api.win32.win32LogicalDisk[i].Name + "\\ " + usageString + "% (Total: " + sizeString + " GB - Free: " + freeString + "GB)"
				status["perfData"] = status["perfData"] + api.win32.win32LogicalDisk[i].Name + "=" + usageString + ";" + api.warning + ";" + api.critical + ";; "
				if critical, _ := strconv.ParseInt(api.critical, 10, 0); critical < usage && status["code"] < "2" {
					status["code"] = "2"
					status["status"] = "CRITICAL"

				}
				if warning, _ := strconv.ParseInt(api.warning, 10, 0); warning < usage && status["code"] < "1" {
					status["code"] = "1"
					status["status"] = "WARNING"
				}
			}
		}
		status["message"] = status["message"] + ""

	case "service":
		if len(api.win32.win32Service) == 0 {
			status["code"] = "3"
			status["status"] = "UNKNOWN"
			status["message"] = "Unknown Service " + api.param + " is not known"
		} else {
			status["code"] = "0"
			status["status"] = "OK"
			services := ""

			for i := range api.win32.win32Service {
				if i > 0 {
					services = services + "\n"
				}

				if api.win32.win32Service[i].State == "Running" {
					services = services + "Service " + api.win32.win32Service[i].Name + " is running"
				} else {
					status["code"] = "2"
					status["status"] = "CRITICAL"
					services = services + "Service " + api.win32.win32Service[i].Name + " is not Running"
				}
			}
			status["message"] = status["status"] + ": " + services
		}

	case "process":
		if len(api.win32.win32Process) == 0 {
			status["code"] = "2"
			status["status"] = "CRITICAL"
			if api.param != "" && api.paramshell == "" {
				status["message"] = "CRITICAL Process " + api.param + " is not running"
			} else {
				status["message"] = "CRITICAL Process " + api.param + " is not running.\n" + api.paramshell
			}
		} else {
			processes := ""
			for i := range api.win32.win32Process {
				processes = processes + api.win32.win32Process[i].Name + "\n" + api.win32.win32Process[i].Shellcommand + "\n"
			}
			status["message"] = "OK Process running: " + processes
			status["code"] = "0"
			status["status"] = "OK"
		}

	case "inventory":
		if api.win32.inventory.Name == "" {
			status["code"] = "3"
			status["status"] = "UNKNOWN"
			status["message"] = "UNKNOWN: Inventory not available"
		} else {
			//data, _ := json.MarshalIndent(api.win32.inventory, "", "  ")

			inv := "Name: " + api.win32.inventory.Name + "." + api.win32.inventory.Domain + " - "
			inv = inv + "Vendor: " + api.win32.inventory.Manufacturer + " - "
			inv = inv + "SN: " + api.win32.inventory.IdentifyingNumber + "\n"
			inv = inv + "CPU: " + strconv.Itoa(int(api.win32.inventory.NumberOfProcessors)) + " Sockets - " + strconv.Itoa(int(api.win32.inventory.NumberOfLogicalProcessors)) + " Cores\n"
			inv = inv + "Memory: " + strconv.Itoa(int(api.win32.inventory.TotalPhysicalMemory/1024/1024/1000)) + " GB\n"

			status["code"] = "0"
			status["status"] = "OK"
			status["message"] = inv
		}

	case "command":
		if api.win32.command.ExitCode == "3" {
			status["code"] = "3"
			status["status"] = "UNKNOWN"
			status["message"] = "Unknown command: " + api.param + " is not known"
		} else {
			status["code"] = api.win32.command.ExitCode
			if api.win32.command.ExitCode == "0" {
				status["status"] = "OK"
			} else if api.win32.command.ExitCode == "1" {
				status["status"] = "WARNING"
			} else if api.win32.command.ExitCode == "2" {
				status["status"] = "CRITICAL"
			} else {
				status["status"] = "UNKNOWN"
			}

			status["message"] = api.win32.command.Output
		}

	case "version":
		status["code"] = "0"
		status["status"] = "OK"
		status["message"] = "Agent Version: " + api.win32.version.Version + " - BuildDate " + api.win32.version.BuildTime + " - Rev: " + api.win32.version.GitHash

	default:
		status["code"] = "3"
		status["status"] = "UNKNOWN"
		status["message"] = "Type is not supported."
	}

}

var (
	status map[string]string
)

func init() {
	status = make(map[string]string)
}

func main() {
	hostPtr := flag.String("host", "localhost", "Host which will receive the request")
	portPtr := flag.Int64("port", 10240, "Port where the host is listening")
	typePtr := flag.String("type", "inventory", "The type for the request. Available types are: multicpu, cpu, disk, memory, service, process")
	warningPtr := flag.String("warning", "0", "The warning value. If its greater than or this value its warning")
	criticalPtr := flag.String("critical", "0", "The critical value. If its greater than or this value")
	paramName := flag.String("param", "", "The name parameter for the Server Daemon")
	paramShell := flag.String("paramshell", "", "The shellcommand parameter for the Server Daemon")
	secretPtr := flag.String("secret", "", "The secret key for the Server Daemon")
	securePtr := flag.Bool("secure", false, "Use http or https as protocol. secure = https")
	flag.Parse()

	req := apiRequest{
		host:  *hostPtr,
		port:  *portPtr,
		types: *typePtr,
		availableTypes: map[string]string{
			"multicpu":  "/api/cpuusagebycore",
			"cpu":       "/api/cpuusage",
			"disk":      "/api/diskusage",
			"memory":    "/api/memoryusage",
			"service":   "/api/services",
			"process":   "/api/processlist",
			"inventory": "/api/systeminfo",
			"command":   "/api/exec",
			"version":   "/api/version",
		},
		warning:    *warningPtr,
		critical:   *criticalPtr,
		param:      *paramName,
		paramshell: *paramShell,
		secret:     *secretPtr,
		secure:     *securePtr,
	}

	resp, err := req.doCurl()

	if err != nil {
		status["code"] = "3"
		status["status"] = "UNKNOWN"
		status["message"] = "Check is running on a problem: " + err.Error()
	} else if resp.StatusCode != http.StatusOK {
		status["code"] = "3"
		status["status"] = "UNKNOWN"
		status["message"] = "Server is require a secretKey which is not provided"
	} else {
		req.parseDataTo(resp)

		req.checkStatus()
	}

	fmt.Println(status["message"] + getPerfData(status["perfData"]))
	exit, _ := strconv.Atoi(status["code"])
	os.Exit(exit)

}

func getPerfData(data string) string {
	if data == "" {
		return ""
	} else {
		return " | " + data
	}
}
