# sma-monitoring-check
This check is the counterpart of the sma-monitoring-agent. With this check you can monitor the agent endpoints

## Usage
```bash
Usage of ./sma-monitoring-check:
  -critical string
    	The critical value. If its greater than or this value (default "0")
  -host string
    	Host which will receive the request (default "localhost")
  -param string
    	The name parameter for the Server Daemon
  -paramshell string
    	The shellcommand parameter for the Server Daemon
  -port int
    	Port where the host is listening (default 10240)
  -secret string
    	The secret key for the Server Daemon
  -secure
    	Use http or https as protocol. secure = https
  -type string
    	The type for the request. Available types are: multicpu, cpu, disk, memory, service, process (default "inventory")
  -warning string
    	The warning value. If its greater than or this value its warning (default "0")
```