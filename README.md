# redBorder Sensor Sandbox Framework

A lightweight, high-performance testing framework for redBorder sensors or other custom agents. It uses Linux namespaces to provide isolated environments (sandboxes) for running mock agents without the overhead of full virtual machines or Docker.

The framework is still under high development. And is in beta phase.
## Overview

The framework allows developers and QA engineers to:
- Run multiple isolated sensor instances on a single host.
- Simulate realistic telemetry traffic (NetFlow, IPFIX, Syslog).
- Test mock SNMP and IPMI agents.
- register IPS sensors and test the intrusion pipeline.
- Inject network failures (latency, loss) for chaos testing.

## Core Components

### Management Tool (`sensor-ctl.sh`)
The main CLI for managing sensors. It handles creation, destruction, logging, and command execution.
- **Start**: `sudo sensor-ctl.sh start <name> [command|type]`
- **Stop**: `sudo sensor-ctl.sh stop <name>`
- **List**: `sensor-ctl.sh list`
- **Logs**: `sudo sensor-ctl.sh logs <name> [-f]`
- **Shell**: `sudo sensor-ctl.sh shell <name>`
- **Restore**: `sudo sensor-ctl.sh restore`

### Shell Autocomplete
A bash completion script is provided to make the CLI easier to use. It suggests commands, running sensor names, and agent types.
```bash
source sensor-ctl-completion.bash
```

### Reboot Persistence
The system automatically saves the configuration of running sensors in `/var/lib/redborder-sensors`. To enable automatic recovery after reboot, a systemd service `redborder-sensors.service` is provided.
```bash
sudo cp redborder-sensors.service /etc/systemd/system/
sudo systemctl enable redborder-sensors.service
```

### Isolation Engine (`sensor-bbox.sh`)
The underlying engine that sets up Mount, Network, and PID namespaces. It creates a sterile root filesystem using BusyBox and `pivot_root`, ensuring no interference with the host system.

### Mock Agents (`programs/go/`)
High-performance mock agents written in Go:
- **Telemetry Agent**: Generates NetFlow v5/v9, IPFIX, and Syslog alerts with advanced traffic models (Poisson, Bursty, Jitter).
- **IPS Agent**: Simulates a Snort-based IPS, supporting registration, heartbeat (Chef Protocol), and HTTPS alert delivery.
- **Proxy Agent**: HTTP/HTTPS proxy supporting anonymous and authenticated (Basic Auth) modes. Useful for testing proxy-aware clients and traffic redirection.
- **SNMP Agent**: Mock SNMPv2c/v3 agent mimicking network devices.
- **IPMI Agent**: Mock IPMI over LAN server supporting sensor readings (Temp, Fan).
- **Redfish Agent**: Supports iLO 5 compatibility, HTTPS, and failure simulation.
  - **Failure Simulation**: Use `-fail-rate <0-100>` or `"fail_rate"` in JSON config to randomize "Critical" health status.
  - **Health Locking**: Set specific component health (e.g., `"health": {"Power": "Critical"}`) in the configuration file.

### Mock Server (`programs/go/server.go`)
A flexible HTTP/HTTPS server for simulating various backend behaviors and validating client requests.

**Features:**
- **Dynamic Routing**: Configurable paths and methods via JSON.
- **Request Validation**:
  - **Basic Auth**: Optional per-endpoint authentication.
  - **Header Check**: Validate that specific headers exist or match expected values.
  - **Body Check**: Ensure the request body matches an exact string.
- **Custom Responses**: Define status codes, response bodies, and custom headers.
- **HTTPS/SSL**: Built-in support for secure connections.
- **Redirects**: Easily simulate 301/302 redirects.

**Usage:**
```bash
sudo ./sensor-ctl.sh start srv /sensor-data/server -config /sensor-data/config-server.json
```

## Getting Started

### 1. Build the Agents
Use the provided `Makefile` to compile all agents as static binaries into the shared volume.
```bash
make
```

### 2. Start a redborder sensor
Launch an IPS sensor with a specific name using shorthand.
```bash
sudo ./sensor-ctl.sh start ips1 ips
```

Launch a telemetry agent with custom networking.
```bash
sudo ./sensor-ctl.sh start s1 --ip 192.168.100.10 --gw 192.168.100.1 telemetry
```

Launch a web proxy (authenticated).
```bash
sudo ./sensor-ctl.sh start proxy1 proxy-agent -config config-proxy-auth.json
```

Run an additional command inside an already active sandbox.
```bash
sudo sensor-ctl.sh exec s1 ping -c 3 8.8.8.8
sudo sensor-ctl.sh exec -d s1 /sensor-data/snmp-agent -config /sensor-data/config-snmp.json
```

### 3. Advanced CLI Usage
- **Persistence**: Use `sudo ./sensor-ctl.sh restore` to recover all sensors after a reboot.
- **Stats**: View real-time resource usage with `sudo ./sensor-ctl.sh stats`.
- **Logs**: Follow logs with `sudo ./sensor-ctl.sh logs <name> -f`.

## Chaos Engineering
The `sensor-chaos.sh` tool allows you to inject network and process failures:
- **Packet Loss**: `sudo ./sensor-chaos.sh loss s1 25%`
- **Latency**: `sudo ./sensor-chaos.sh delay s1 150ms`
- **Interface Down**: `sudo ./sensor-chaos.sh down s1`
- **Port Blocking**: `sudo ./sensor-chaos.sh block s1 161 udp`
- **Process Kill**: `sudo ./sensor-chaos.sh kill s1`
- **Status/Clear**: Use `status` to view impairments and `clear` to remove them.

## Packaging (RPM)

You can package the entire framework into an RPM for easy distribution on RHEL/Fedora-based systems.

### Manual Build
Ensure you have `rpm-build`, `golang`, `gcc`, `make`, and `glibc-static` installed on your host.
```bash
./build-rpm.sh
```
The resulting RPM will be available in `/tmp/rpmbuild-sensors/RPMS/x86_64/`.

## Networking Architecture

The framework uses a **Bridge-per-Subnet** model:
- Each sensor is connected to a Linux bridge via a `veth` pair.
- Subnets are automatically managed (e.g., `192.168.100.0/24` for ID 100).
- Outbound traffic is NAT'd through the host's default interface.
- Standard gateway IPs are assigned to bridges to ensure compatibility with automation tools.

## Advanced Features

### Multi-Instance Isolation
Each sensor instance has its own identity. The framework exports the `SENSOR_NAME` environment variable, allowing agents to isolate their state files (e.g., `ips-state-ips1.json`) within the shared volume.

## Requirements
- Linux kernel with Namespace support (`CONFIG_NAMESPACES`).
- `iproute2`, `iptables`, `util-linux`, `wget`.
- Go (for building agents).

### Automated Build
The project includes CI/CD configurations for both **GitHub Actions** and **GitLab CI** (see below) that automatically build the RPM on every push to the `main` branch or when a new tag is created.

## CI/CD Pipeline
GitHub Actions workflows are included in `.github/workflows/` to automate the RPM building process and binary verification. It uses a Fedora container to run the `build-rpm.sh` script and produces artifacts for each release.

Alternatively, a `.gitlab-ci.yml` is also provided for GitLab environments.

## License
This project is licensed under the **MIT License**. See the `LICENSE` file for details.

---
**Author**: David Vanhoucke <dvanhoucke@redborder.com>  
© 2026 redBorder Networks
