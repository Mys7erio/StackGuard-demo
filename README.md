# Overview
This project implements a runtime security observability solution leveraging eBPF-based tracing with Tetragon to monitor:

 1. Process execution events (execve) and their arguments.

 2. Outbound TCP network connections (tcp_connect).

The solution enriches these observability events with machine identity mapping (e.g., environment variables like OPENAI_API_KEY, mock mappings) and applies simple detection logic to flag suspicious behavior. The entire pipeline is centered around Tetragon’s eBPF runtime instrumentation with a custom Python collector that consumes, enriches, and analyzes event streams.


# UPDATE

Do not run the tetragon as a system service for running the updated script. Stop the service if running already:

> [!IMPORTANT]
> The following scripts were tested on Python 3.12. Make sure the python binary available on your system is at the same location as mentioned in the newly added `tcp-data-monitor.yaml` file. If not, do your due diligence, and modify the policy file with the updated location of your Python binary on your system. 

`sudo systemctl stop tetragon`

Run the tetragon daemon in a seperate terminal: `sudo /usr/local/bin/tetragon --tracing-policy /home/shakir/StackGuard-demo/tetragon-policies/tcp-data-monitor.yaml --export-filename /var/log/tetragon/tetragon.log`


In a seperate terminal, verify the policy has been loaded: `sudo tetra tracingpolicy list`
```bash
shakir@ubuntu:~/StackGuard-demo$ sudo tetra tracingpolicy list
ID   NAME               STATE     FILTERID   NAMESPACE   SENSORS          KERNELMEMORY   MODE
1    tcp-data-monitor   loading   0          (global)    generic_kprobe   0 B            unknown
shakir@ubuntu:~/StackGuard-demo$
```

Now run this command to start monitoring for network traffic, and print only the output from the policy we just loaded: `sudo tetra getevents --policy-names tcp-data-monitor | jq`


Now in another seperate terminal, run the chatbot.py python script. Type `sudo make` to place it to the correct location automatically (/usr/local/bin/chatbot).

> [!TIP]
> The location of the python script or the name is irrelevant as of now. Since we're monitoring all network communications happening via the python3.12 binary.


Check the terminal where you ran the `tetra getevents` command to see all network traffic happening via the chatbot.

> [!CAUTION]
> Since the chatbot.py script is making a get request to `https://google.com/`, all communication is TLS encrypted, and hence being able to search through the network responses or applying regex to look for patterns is not possible. 


# Tech Stack

## Tetragon

Tetragon is an eBPF-based Linux kernel tracing tool running as a system service that captures real-time process execution and network connection events with minimal overhead. It performs the following functions:

 - Captures kernel-level execve and tcp_connect events via configurable TracingPolicies
 - Emits rich JSON event streams over a gRPC Unix socket

## Python Collector

A user-space collector program written in Python3 is responsible for consuming the JSON event stream from Tetragon. It connects to this stream, parses and normalizes these events, infers machine identities from environment variables or mock mappings, applies simple detection logic to flag suspicious activity (like unexpected shell launches or unauthorized network connections), and outputs enriched JSON logs for observability and alerting.


# Environment Setup
## Prerequisites
- **Linux Kernel**: Ensure you are running a compatible Linux kernel that supports eBPF (Tested on Linux kernel `6.14.0-24-generic`)
- **Tetragon**: Tetragon running as a system service [Instructions](https://tetragon.io/docs/installation/package/)
- **Tetra CLI**: Tetra CLI (tested on `CLI version: v1.5.0`) [Instructions](https://tetragon.io/docs/installation/tetra-cli/)
- **Python 3**: Python3 (Tested on `Python 3.12.3`)

## Installation

1. Ensure tetragon is running as a system service:
```bash
$ sudo systemctl status tetragon
```
### Output
```bash
shakir@ubuntu:~$ sudo systemctl status tetragon
● tetragon.service - Tetragon eBPF-based Security Observability and Runtime Enforcement
     Loaded: loaded (/usr/lib/systemd/system/tetragon.service; enabled; preset: enabled)
     Active: active (running) since Fri 2025-08-08 19:49:18 IST; 3h 21min ago
       Docs: https://tetragon.io/
   Main PID: 70945 (tetragon)
      Tasks: 11 (limit: 4546)
     Memory: 63.2M (peak: 154.2M)
        CPU: 1min 15.263s
     CGroup: /system.slice/tetragon.service
             └─70945 /usr/local/bin/tetragon

Aug 08 21:44:00 ubuntu tetragon[70945]: level=info msg="Unloading sensor generic_kprobe"
Aug 08 21:44:00 ubuntu tetragon[70945]: level=info msg="Sensor unloaded" sensor=generic_kprobe maps-error=[]
Aug 08 21:44:00 ubuntu tetragon[70945]: level=warn msg="Failed to match id:1" error="getting entry from genericKprobeTable failed with: invalid>
Aug 08 21:44:15 ubuntu tetragon[70945]: level=warn msg="Server AddTracingPolicy request failed" error="validation failed: spec.kprobes[0].args[>
Aug 08 21:44:30 ubuntu tetragon[70945]: level=info msg="Added kprobe" return=false function=tcp_connect override=false
Aug 08 21:44:30 ubuntu tetragon[70945]: level=info msg="BTF file: using metadata file" metadata=/sys/kernel/btf/vmlinux
Aug 08 21:44:30 ubuntu tetragon[70945]: level=info msg="Loading sensor" name=generic_kprobe
Aug 08 21:44:30 ubuntu tetragon[70945]: level=info msg="Loading kernel version 6.14.6"
Aug 08 21:44:33 ubuntu tetragon[70945]: level=info msg="Loaded generic kprobe sensor: /usr/local/lib/tetragon/bpf/bpf_multi_kprobe_v612.o -> kp>
Aug 08 21:44:33 ubuntu tetragon[70945]: level=info msg="Loaded sensor successfully" sensor=generic_kprobe
```

2. Load the Tetragon policies:
```bash
$ sudo tetra policy load ./policies/tcp_connect.json
```
```bash
# Check if the policy has been loaded:
$ sudo tetra tracingpolicy list
#
# Should show something like this:
# ID   NAME             STATE     FILTERID   NAMESPACE   SENSORS          KERNELMEMORY   MODE
# 2    sg-tcp-connect   enabled   0          (global)    generic_kprobe   13.85 MB       enforce
```


3. Run the collector script using sudo privilleges:
```bash
python3 collector.py
```

4. Mimick malicious and regular activities:

In a separate terminal, run the following commands:

```bash
# Activity which we're monitoring: OpenAI API call
OPENAI_API_KEY=insert-key-here curl openai.com

# Activity which we don't have a rule for
CLOSEDAI_API_KEY=insert-key-here curl openai.com
```


5. Check the collector output:
```json
shakir@ubuntu:~/tetragon$ sudo python3 collector3.py |jq
{
  "ts": "2025-08-08T17:44:07.730801281Z",
  "category": "exec",
  "hostname": "ubuntu",
  "event": "process_exec",
  "pid": 72704,
  "binary": "/usr/bin/curl",
  "args": "openai.com",
  "parent": {
    "pid": 72685,
    "binary": "/bin/bash"
  },
  "identity": {
    "type": "env",
    "key": "OPENAI_API_KEY",
    "present": true,
    "id": "openai_api_key-present"
  }
}
{
  "ts": "2025-08-08T17:44:09.979226315Z",
  "category": "kprobe",
  "hostname": "ubuntu",
  "event": "kprobe:tcp_connect",
  "pid": 72704,
  "binary": "/usr/bin/curl",
  "args": "openai.com",
  "identity": {
    "type": "env",
    "key": "OPENAI_API_KEY",
    "present": true,
    "id": "openai_api_key-present"
  },
  "network": {
    "saddr": "192.168.23.137",
    "daddr": "104.18.33.45",
    "sport": 41724,
    "dport": 80,
    "family": "AF_INET",
    "protocol": "IPPROTO_TCP"
  }
}
{
  "ts": "2025-08-08T17:44:10.348672508Z",
  "category": "other",
  "hostname": "ubuntu",
  "event": "other"
}
```


```json
shakir@ubuntu:~/tetragon$ sudo python3 collector3.py |jq
{
  "ts": "2025-08-08T17:46:48.861223381Z",
  "category": "exec",
  "hostname": "ubuntu",
  "event": "process_exec",
  "pid": 72726,
  "binary": "/usr/bin/curl",
  "args": "openai.com",
  "parent": {
    "pid": 72685,
    "binary": "/bin/bash"
  },
  "identity": {
    "type": "argv",
    "name": "openai",
    "id": "argv-openai"
  }
}
{
  "ts": "2025-08-08T17:46:49.149597775Z",
  "category": "kprobe",
  "hostname": "ubuntu",
  "event": "kprobe:tcp_connect",
  "pid": 72726,
  "binary": "/usr/bin/curl",
  "args": "openai.com",
  "identity": {
    "type": "argv",
    "name": "openai",
    "id": "argv-openai"
  },
  "network": {
    "saddr": "192.168.23.137",
    "daddr": "172.64.154.211",
    "sport": 53852,
    "dport": 80,
    "family": "AF_INET",
    "protocol": "IPPROTO_TCP"
  }
}
{
  "ts": "2025-08-08T17:46:49.340366471Z",
  "category": "other",
  "hostname": "ubuntu",
  "event": "other"
}

```
