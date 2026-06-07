#!/usr/bin/env bash

# sensor-ctl.sh - Manage multiple redborder sensors
# Usage: sudo ./sensor-ctl.sh {start|stop|list|shell} [name]

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
STATE_DIR="/tmp/redborder-sensors"
PERSIST_DIR="/var/lib/redborder-sensors"
BIN_DIR="$PERSIST_DIR/bin"
mkdir -p "$STATE_DIR" "$PERSIST_DIR" "$BIN_DIR"

BUSYBOX="$BIN_DIR/busybox"
BUSYBOX_URL="https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"

if [ ! -f "$BUSYBOX" ]; then
    echo "[+] Downloading static BusyBox binary to $BIN_DIR..."
    wget -q "$BUSYBOX_URL" -O "$BUSYBOX"
    chmod +x "$BUSYBOX"
fi

# Ensure the script is run as root for most commands
if [ "$EUID" -ne 0 ] && [ "$1" != "list" ]; then
    echo "[-] This script requires root privileges. Please run with sudo."
    exit 1
fi

function get_free_id() {
    local id=100
    while [ -f "$STATE_DIR/id-$id" ]; do
        id=$((id+1))
    done
    echo "$id"
}

function list_sandboxes() {
    printf "%-15s %-10s %-15s %-10s %-10s %-10s\n" "NAME" "PID" "IP" "STATUS" "CPU" "MEM"
    printf "%-15s %-10s %-15s %-10s %-10s %-10s\n" "----" "---" "--" "------" "---" "---"
    for f in "$STATE_DIR"/*.pid; do
        [ -e "$f" ] || continue
        name=$(basename "$f" .pid)
        pid=$(cat "$f")
        ip_file="$STATE_DIR/$name.ip"
        ip=$(cat "$ip_file" 2>/dev/null || echo "N/A")
        
        cpu="-"
        mem="-"
        
        if kill -0 "$pid" 2>/dev/null; then
            status="Running"
            # Get the PID namespace ID for the sandbox
            ns_id=$(ps -p "$pid" -o pidns= 2>/dev/null | tr -d ' ')
            if [ -n "$ns_id" ]; then
                # Get all PIDs in that namespace
                pids=$(ps -e -o pid,pidns --no-headers 2>/dev/null | awk -v ns="$ns_id" '$2 == ns {print $1}' | tr '\n' ',' | sed 's/,$//')
                if [ -n "$pids" ]; then
                    usage=$(ps -p "$pids" -o %cpu,%mem --no-headers 2>/dev/null | awk '{cpu+=$1; mem+=$2} END {print cpu, mem}')
                    cpu=$(echo "$usage" | awk '{printf "%.1f%%", $1}')
                    mem=$(echo "$usage" | awk '{printf "%.1f%%", $2}')
                fi
            fi
        else
            status="Stopped"
        fi
        printf "%-15s %-10s %-15s %-10s %-10s %-10s\n" "$name" "$pid" "$ip" "$status" "$cpu" "$mem"
    done
}

function show_stats() {
    echo "[+] Gathering real-time stats (Ctrl+C to stop)..."
    while true; do
        clear
        echo "Redborder Sensor Sandbox Stats - $(date)"
        echo ""
        list_sandboxes
        sleep 2
    done
}

function show_logs() {
    local name=$1
    local follow=$2
    if [ -z "$name" ]; then
        echo "Usage: $0 logs <name> [-f]"
        exit 1
    fi
    
    local log_file="$STATE_DIR/$name.log"
    if [ ! -f "$log_file" ]; then
        echo "[-] Log file for sensor '$name' not found."
        exit 1
    fi
    
    if [ "$follow" == "-f" ]; then
        tail -f "$log_file"
    else
        cat "$log_file"
    fi
}

function stop_sandbox() {
    local name=$1
    if [ -z "$name" ]; then
        echo "Usage: $0 stop <name>"
        exit 1
    fi
    
    if [[ ! "$name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "[-] Error: Invalid sensor name '$name'. Use only alphanumeric, dash, and underscore."
        exit 1
    fi
    
    local pid_file="$STATE_DIR/$name.pid"
    if [ ! -f "$pid_file" ]; then
        echo "[-] Sandbox '$name' not found."
        return
    fi
    
    local pid=$(cat "$pid_file")
    local id_file=""
    if ls "$STATE_DIR/id-"* &>/dev/null; then
        id_file=$(ls "$STATE_DIR/id-"* | xargs grep -l "$name" 2>/dev/null)
    fi
    
    echo "[+] Stopping sensor '$name' (PID $pid)..."
    
    # Try to kill gracefully then forcefully
    kill "$pid" 2>/dev/null || true
    sleep 1
    kill -9 "$pid" 2>/dev/null || true
    
    # Cleanup network
    local host_iface="veth-$name"
    local ip_file="$STATE_DIR/$name.ip"
    local container_ip=$(cat "$ip_file" 2>/dev/null)
    local subnet_prefix=$(echo "$container_ip" | sed 's/\.[0-9]*$/\.0/')
    local br_id=$(echo "$subnet_prefix" | cut -d. -f3)
    local br_iface="br-$br_id"

    if ip link show "$host_iface" &>/dev/null; then
        echo "[+] Removing network interface $host_iface..."
        
        # Cleanup NAT/Forwarding rules
        local phys_iface=$(ip route | grep default | awk '{print $5}' | head -n 1)
        iptables -D FORWARD -i "$host_iface" -j ACCEPT 2>/dev/null || true
        iptables -D FORWARD -o "$host_iface" -j ACCEPT 2>/dev/null || true
        
        ip link del "$host_iface"
    fi

    # Cleanup bridge if empty
    if [ -n "$br_id" ] && ip link show "$br_iface" &>/dev/null; then
        # Check if any other veths are still attached to this bridge
        local active_ports=$(ip link show master "$br_iface" 2>/dev/null | grep -c "veth-")
        if [ "$active_ports" -eq 0 ]; then
            echo "[+] Removing empty bridge $br_iface..."
            ip link del "$br_iface"
            
            # Cleanup bridge-specific iptables rules
            if [ -n "$phys_iface" ]; then
                iptables -t nat -D POSTROUTING -s "$subnet_prefix/24" -o "$phys_iface" -j MASQUERADE 2>/dev/null || true
                iptables -D FORWARD -i "$br_iface" -j ACCEPT 2>/dev/null || true
                iptables -D FORWARD -o "$br_iface" -j ACCEPT 2>/dev/null || true
            fi
        fi
    fi
    
    # Remove state files
    rm -f "$pid_file" "$STATE_DIR/$name.ip"
    [ -n "$id_file" ] && rm -f "$id_file"
    rm -rf "$PERSIST_DIR/$name"
    
    echo "[+] Sandbox '$name' stopped and cleaned up."
}
function start_sandbox() {
    local name=$1
    shift

    local custom_ip=""
    local custom_gw=""

    if [ -z "$name" ]; then
        echo "Usage: $0 start <name> [--ip <ip>] [--gw <gw>] [command...]"
        exit 1
    fi

    if [[ ! "$name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "[-] Error: Invalid sensor name '$name'. Use only alphanumeric, dash, and underscore."
        exit 1
    fi

    # Parse optional flags
    while [[ "$1" == --* ]]; do
        case "$1" in
            --ip=*)
                custom_ip="${1#--ip=}"
                shift
                ;;
            --ip)
                custom_ip="$2"
                shift 2
                ;;
            --gw=*)
                custom_gw="${1#--gw=}"
                shift
                ;;
            --gw)
                custom_gw="$2"
                shift 2
                ;;
            *)
                echo "[-] Error: Unknown option '$1'"
                echo "Usage: $0 start <name> [--ip <ip>] [--gw <gw>] [command...]"
                exit 1
                ;;
        esac
    done

    local cmd=("$@")

    # Check name length (veth- prefix + name must be <= 15 chars)
    if [ ${#name} -gt 10 ]; then
        echo "[-] Error: Sandbox name '$name' is too long (${#name} chars). Max 10 characters allowed."
        exit 1
    fi

    if [ -f "$STATE_DIR/$name.pid" ]; then
        local pid=$(cat "$STATE_DIR/$name.pid")
        if kill -0 "$pid" 2>/dev/null; then
            echo "[-] Sandbox '$name' is already running (PID $pid)."
            exit 1
        else
            echo "[!] Found stale PID file for '$name'. Cleaning up..."
            # Only cleanup volatile state, keep persistence
            rm -f "$STATE_DIR/$name.pid" "$STATE_DIR/$name.ip"
        fi
    fi

    local id=""
    local host_ip=""
    local container_ip=""
    local subnet_mask="24"

    if [ -n "$custom_ip" ]; then
        container_ip="$custom_ip"
        if [ -n "$custom_gw" ]; then
            host_ip="$custom_gw"
        else
            # Try to guess gateway (replace last octet with .1)
            host_ip=$(echo "$container_ip" | sed 's/\.[0-9]*$/\.1/')
            echo "[!] No gateway specified, guessing $host_ip"
        fi
        # Subnet for NAT
        local subnet_prefix=$(echo "$container_ip" | sed 's/\.[0-9]*$/\.0/')
    else
        id=$(get_free_id)
        echo "$name" > "$STATE_DIR/id-$id"
        local subnet="192.168.$id"
        host_ip="$subnet.1"
        container_ip="$subnet.2"
        local subnet_prefix="$subnet.0"
    fi

    echo "[+] Starting sensor '$name' (IP: $container_ip, GW: $host_ip)..."

    # If no command provided, use a keep-alive loop
    if [ ${#cmd[@]} -eq 0 ]; then
        cmd=("/bin/sh" "-c" "while true; do sleep 1d; done")
    elif [[ "${cmd[0]}" == -* ]]; then
        echo "[!] Warning: First command argument '${cmd[0]}' starts with '-'. Did you forget the command path?"
        echo "    Usage: $0 start <name> [--ip <ip>] [--gw <gw>] <command> [args...]"
    fi

    # Launch in background
    "$SCRIPT_DIR/sensor-bbox.sh" "--name=$name" "${cmd[@]}" > "$STATE_DIR/$name.log" 2>&1 &

    local unshare_pid=$!
    
    # Wait for the child process to be created
    # We poll for up to 5 seconds
    local container_pid=""
    for i in {1..50}; do
        container_pid=$(pgrep -P "$unshare_pid" | head -n 1)
        if [ -n "$container_pid" ] && [ -d "/proc/$container_pid/ns/net" ]; then
            break
        fi
        sleep 0.1
    done
    
    if [ -z "$container_pid" ]; then
        echo "[-] Failed to start sensor. Check $STATE_DIR/$name.log for details."
        # Try to cat the log if it exists
        [ -f "$STATE_DIR/$name.log" ] && cat "$STATE_DIR/$name.log"
        rm -f "$STATE_DIR/id-$id"
        exit 1
    fi
    
    echo "$container_pid" > "$STATE_DIR/$name.pid"
    echo "$container_ip" > "$STATE_DIR/$name.ip"
    
    # Save for persistence
    local pdir="$PERSIST_DIR/$name"
    mkdir -p "$pdir"
    echo "$container_ip" > "$pdir/ip"
    echo "$host_ip" > "$pdir/gw"
    if [ ${#cmd[@]} -gt 0 ]; then
        printf "%s\n" "${cmd[@]}" > "$pdir/start_cmd"
    else
        rm -f "$pdir/start_cmd"
    fi

    # Setup Network
    local host_iface="veth-$name"
    local ns_iface="veth-ns"
    # Bridge name must be < 15 chars. br-<ID> or br-<sum>
    local br_id=$(echo "$subnet_prefix" | cut -d. -f3)
    if [ "$br_id" == "50" ]; then br_id="50"; fi # Keep 50 for custom
    local br_iface="br-$br_id"
    
    echo "[+] Configuring network for PID $container_pid..."
    
    # Create bridge if it doesn't exist
    if ! ip link show "$br_iface" &>/dev/null; then
        echo "[+] Creating bridge $br_iface for subnet $subnet_prefix/24..."
        ip link add "$br_iface" type bridge
        ip addr add "$host_ip/24" dev "$br_iface"
        ip link set "$br_iface" up
        # Enable proxy_arp on bridge
        if [ -f "/proc/sys/net/ipv4/conf/$br_iface/proxy_arp" ]; then
            echo 1 > "/proc/sys/net/ipv4/conf/$br_iface/proxy_arp"
        fi
    fi

    ip link add "$host_iface" type veth peer name "$ns_iface"
    ip link set "$host_iface" master "$br_iface"
    ip link set "$host_iface" up
    ip link set "$ns_iface" netns "$container_pid"
    
    "$BUSYBOX" nsenter -t "$container_pid" -n ip addr add "$container_ip/24" dev "$ns_iface"
    "$BUSYBOX" nsenter -t "$container_pid" -n ip link set "$ns_iface" up
    "$BUSYBOX" nsenter -t "$container_pid" -n ip route add default via "$host_ip"
    
    # Setup NAT
    # Try to find physical interface
    local phys_iface=$(ip route | grep default | awk '{print $5}' | head -n 1)
    if [ -n "$phys_iface" ]; then
        # Check if the MASQUERADE rule already exists for this subnet
        iptables -t nat -C POSTROUTING -s "$subnet_prefix/24" -o "$phys_iface" -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -s "$subnet_prefix/24" -o "$phys_iface" -j MASQUERADE
        
        # Forwarding rules for the bridge
        iptables -C FORWARD -i "$br_iface" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$br_iface" -j ACCEPT
        iptables -C FORWARD -o "$br_iface" -j ACCEPT 2>/dev/null || iptables -A FORWARD -o "$br_iface" -j ACCEPT
    fi
    
    echo "[+] Sandbox '$name' is up and running."
    echo "    - Container PID: $container_pid"
    echo "    - Container IP:  $container_ip"
    echo "    - Host Gateway:  $host_ip"
}

function enter_shell() {
    local name=$1
    if [ -z "$name" ]; then
        echo "Usage: $0 shell <name>"
        exit 1
    fi
    
    if [[ ! "$name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        echo "[-] Error: Invalid sensor name '$name'. Use only alphanumeric, dash, and underscore."
        exit 1
    fi
    
    local pid_file="$STATE_DIR/$name.pid"
    if [ ! -f "$pid_file" ]; then
        echo "[-] Sandbox '$name' not found."
        exit 1
    fi
    
    local pid=$(cat "$pid_file")
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "[-] Sandbox '$name' is not running."
        exit 1
    fi
    
    echo "[+] Entering sensor '$name'..."
    "$BUSYBOX" nsenter -t "$pid" -m -u -i -n -p /bin/env -i SENSOR_NAME="$name" PATH=/bin:/sbin TERM="$TERM" /bin/sh --login
}

function exec_command() {
    local name=$1
    shift
    
    local detached=0
    if [ "$1" == "-d" ]; then
        detached=1
        shift
    fi
    
    local cmd=("$@")
    
    if [ -z "$name" ] || [ ${#cmd[@]} -eq 0 ]; then
        echo "Usage: $0 exec <name> [-d] <command> [args...]"
        exit 1
    fi
    
    local pid_file="$STATE_DIR/$name.pid"
    if [ ! -f "$pid_file" ]; then
        echo "[-] Sandbox '$name' not found."
        exit 1
    fi
    
    local pid=$(cat "$pid_file")
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "[-] Sandbox '$name' is not running."
        exit 1
    fi
    
    if [ "$detached" -eq 1 ]; then
        local pdir="$PERSIST_DIR/$name/execs"
        mkdir -p "$pdir"
        
        # Check if we are already restoring this command (avoid duplicates)
        local is_duplicate=0
        for f in "$pdir"/*; do
            [ -e "$f" ] || continue
            if diff <(printf "%s\n" "${cmd[@]}") "$f" &>/dev/null; then
                is_duplicate=1
                break
            fi
        done

        if [ "$is_duplicate" -eq 0 ]; then
            local exec_id=$(ls "$pdir" 2>/dev/null | wc -l)
            printf "%s\n" "${cmd[@]}" > "$pdir/$exec_id"
        fi

        echo "[+] Running command in background, logging to $STATE_DIR/$name.log"
        "$BUSYBOX" nsenter -t "$pid" -m -u -i -n -p /bin/env -i SENSOR_NAME="$name" PATH=/bin:/sbin TERM="$TERM" "${cmd[@]}" >> "$STATE_DIR/$name.log" 2>&1 &
    else
        "$BUSYBOX" nsenter -t "$pid" -m -u -i -n -p /bin/env -i SENSOR_NAME="$name" PATH=/bin:/sbin TERM="$TERM" "${cmd[@]}"
    fi
}

function restore_sandboxes() {
    echo "[+] Restoring sensors from $PERSIST_DIR..."
    for d in "$PERSIST_DIR"/*/; do
        [ -d "$d" ] || continue
        name=$(basename "$d")
        [ "$name" == "bin" ] && continue
        
        if [ -f "$STATE_DIR/$name.pid" ]; then
            pid=$(cat "$STATE_DIR/$name.pid")
            if kill -0 "$pid" 2>/dev/null; then
                echo "[!] Sensor '$name' is already running (PID $pid). Skipping..."
                continue
            fi
        fi

        echo "[+] Restoring sensor '$name'..."
        
        local ip=$(cat "$d/ip" 2>/dev/null)
        local gw=$(cat "$d/gw" 2>/dev/null)
        
        local start_args=("$name")
        [ -n "$ip" ] && start_args+=("--ip" "$ip")
        [ -n "$gw" ] && start_args+=("--gw" "$gw")

        if [ -f "$d/start_cmd" ]; then
            mapfile -t cmd < "$d/start_cmd"
            start_sandbox "${start_args[@]}" "${cmd[@]}"
        else
            start_sandbox "${start_args[@]}"
        fi
        
        if [ -d "$d/execs" ]; then
            # Use a sorted list of exec IDs to maintain order
            for f in $(ls "$d/execs/" | sort -n); do
                [ -f "$d/execs/$f" ] || continue
                mapfile -t exec_cmd < "$d/execs/$f"
                echo "[+]   Re-running detached command: ${exec_cmd[*]}"
                exec_command "$name" -d "${exec_cmd[@]}"
            done
        fi
    done
}

case "$1" in
    start)
        shift
        start_sandbox "$@"
        ;;
    stop)
        shift
        stop_sandbox "$@"
        ;;
    restore)
        restore_sandboxes
        ;;
    list)
        list_sandboxes
        ;;
    stats)
        show_stats
        ;;
    logs)
        shift
        show_logs "$@"
        ;;
    exec)
        shift
        exec_command "$@"
        ;;
    shell)
        shift
        enter_shell "$@"
        ;;
    *)
        echo "Usage: $0 {start|stop|list|stats|logs|exec|shell|restore} [name]"
        echo ""
        echo "Commands:"
        echo "  start <name> [--ip <ip>] [--gw <gw>] [command]   Start a new sensor"
        echo "  stop <name>                                      Stop a running sensor"
        echo "  restore                                          Restore all sensors from persistent config"
        echo "  list                                             List all sensors"
        echo "  stats                                            Show real-time resource usage"
        echo "  logs <name> [-f]                                 Show sensor logs (-f to follow)"
        echo "  exec <name> [-d] <command>                       Run a command in a running sensor (-d for background)"
        echo "  shell <name>                                     Enter sensor shell"
        exit 1
        ;;
esac
