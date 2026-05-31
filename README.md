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
- **Start**: `sudo sensor-ctl.sh start <name> [command]`
- **Stop**: `sudo sensor-ctl.sh stop <name>`
- **List**: `sensor-ctl.sh list`
- **Logs**: `sudo sensor-ctl.sh logs <name> [-f]`
- **Shell**: `sudo sensor-ctl.sh shell <name>`

### Isolation Engine (`sensor-bbox.sh`)
The underlying engine that sets up Mount, Network, and PID namespaces. It creates a sterile root filesystem using BusyBox and `pivot_root`, ensuring no interference with the host system.

### Mock Agents (`programs/go/`)
High-performance mock agents written in Go:
- **Telemetry Agent**: Generates NetFlow v5/v9, IPFIX, and Syslog alerts with advanced traffic models (Poisson, Bursty, Jitter).
- **IPS Agent**: Simulates a Snort-based IPS, supporting registration, heartbeat, and HTTPS alert delivery.
- **SNMP/IPMI Agents**: Mock device agents for testing discovery and monitoring.

## Getting Started

### 1. Build the Agents
Use the provided `Makefile` to compile all agents as static binaries into the shared volume.
```bash
make
```

### 2. Start a redborder sensor
Launch an IPS sensor with a specific name and configuration.
```bash
sudo ./sensor-ctl.sh start ips1 /sensor-data/ips-agent -config /sensor-data/config-ips.json
```

### 3. redborder sensor monitor
View real-time resource usage across all active sensors.
```bash
sudo ./sensor-ctl.sh stats
```

## Networking Architecture

The framework uses a **Bridge-per-Subnet** model:
- Each sensor is connected to a Linux bridge via a `veth` pair.
- Subnets are automatically managed (e.g., `192.168.100.0/24` for ID 100).
- Outbound traffic is NAT'd through the host's default interface.
- Standard gateway IPs are assigned to bridges to ensure compatibility with automation tools.

## Advanced Features

### Multi-Instance Isolation
Each sensor instance has its own identity. The framework exports the `SENSOR_NAME` environment variable, allowing agents to isolate their state files (e.g., `ips-state-ips1.json`) within the shared volume.

### Chaos Engineering
Use `sensor-chaos.sh` to inject network impairments directly into a snesors interface:
```bash
sudo sensor-chaos.sh loss ips1 10%
sudo sensor-chaos.sh delay ips1 100ms
```

## Requirements
- Linux kernel with Namespace support (`CONFIG_NAMESPACES`).
- `iproute2`, `iptables`, `util-linux`, `wget`.
- Go (for building agents).

## CI/CD Pipeline
GitHub Actions workflows are included in `.github/workflows/` to automate the RPM building process and binary verification. It uses a Fedora container to run the `build-rpm.sh` script and produces artifacts for each release.

Alternatively, a `.gitlab-ci.yml` is also provided for GitLab environments.

## License
This project is licensed under the **MIT License**. See the `LICENSE` file for details.

---
**Author**: David Vanhoucke <dvanhoucke@redborder.com>  
© 2026 redBorder Networks
