#!/usr/bin/env bash

# sensor-ctl.sh - Manage multiple redborder sensors
# Usage: sudo ./sensor-ctl.sh {start|stop|list|shell} [name]

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
STATE_DIR="/tmp/redborder-sensors"
PERSIST_DIR="/var/lib/redborder-sensors"
BIN_DIR="$PERSIST_DIR/bin"
mkdir -p "$STATE_DIR" "$PERSIST_DIR" "$BIN_DIR"



# Ensure the script is run as root for most commands
if [ "$EUID" -ne 0 ] && [ "$1" != "list" ] && [ "$1" != "__complete" ]; then
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
    
    # Cleanup cgroup
    local cg_dir="/sys/fs/cgroup/redborder-sensors/$name"
    if [ -d "$cg_dir" ]; then
        echo "[+] Removing cgroup $cg_dir..."
        rmdir "$cg_dir" 2>/dev/null || true
    fi
    
    echo "[+] Sandbox '$name' stopped and cleaned up."
}
function start_sandbox() {
    local name=$1
    shift

    local custom_ip=""
    local custom_gw=""
    local use_macvlan=0

    if [ -z "$name" ]; then
        echo "Usage: $0 start <name> [--ip <ip>] [--gw <gw>] [--mac] [command|type]"
        echo "Example: $0 start ips1 ips"
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
            --mac)
                use_macvlan=1
                shift
                ;;
            *)
                echo "[-] Error: Unknown option '$1'"
                echo "Usage: $0 start <name> [--ip <ip>] [--gw <gw>] [--mac] [command...]"
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

    # Shorthand resolution
    if [ ${#cmd[@]} -gt 0 ]; then
        case "${cmd[0]}" in
            ips)
                cmd=("/sensor-data/ips-agent" "-config" "/sensor-data/config-ips.json" "${cmd[@]:1}")
                ;;
            snmp)
                cmd=("/sensor-data/snmp-agent" "-config" "/sensor-data/config-snmp.json" "${cmd[@]:1}")
                ;;
            ipmi)
                cmd=("/sensor-data/ipmi-agent" "-config" "/sensor-data/config-ipmi.json" "${cmd[@]:1}")
                ;;
            redfish)
                cmd=("/sensor-data/redfish-agent" "-config" "/sensor-data/config-redfish.json" "${cmd[@]:1}")
                ;;
            webproxy)
                cmd=("/sensor-data/webproxy-agent" "-config" "/sensor-data/config-webproxy-anon.json" "${cmd[@]:1}")
                ;;
            telemetry)
                cmd=("/sensor-data/telemetry-agent" "-config" "/sensor-data/config.json" "${cmd[@]:1}")
                ;;
            sflow)
                cmd=("/sensor-data/telemetry-agent" "-config" "/sensor-data/config-sflow.json" "${cmd[@]:1}")
                ;;
            webserver)
                cmd=("/sensor-data/webserver" "-config" "/sensor-data/config-webserver.json" "${cmd[@]:1}")
                ;;
            proxy)
                cmd=("/sensor-data/proxy" "-config" "/sensor-data/config-proxy.json" "${cmd[@]:1}")
                ;;
        esac
    fi

    # Smart path resolution for all arguments
    for i in "${!cmd[@]}"; do
        # If it's not an absolute path, try to find it in /sensor-data
        if [[ "${cmd[$i]}" != /* ]] && [ -f "$SCRIPT_DIR/sensor-volume/${cmd[$i]}" ]; then
            cmd[$i]="/sensor-data/${cmd[$i]}"
        fi
    done

    # Copy sensor-bbox.sh to a publicly accessible directory to allow execution inside user namespace
    export HOST_SHARED_DIR="$SCRIPT_DIR/sensor-volume"
    cp "$SCRIPT_DIR/sensor-bbox.sh" /var/lib/redborder-sensors/bin/sensor-bbox.sh
    chmod +x /var/lib/redborder-sensors/bin/sensor-bbox.sh

    # Launch in background
    /var/lib/redborder-sensors/bin/sensor-bbox.sh "--name=$name" "${cmd[@]}" > "$STATE_DIR/$name.log" 2>&1 &

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
    echo "$use_macvlan" > "$pdir/mac"
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
    
    # Try to find physical interface
    local phys_iface=$(ip route | grep default | awk '{print $5}' | head -n 1)

    if [ "$use_macvlan" -eq 1 ]; then
        if [ -z "$phys_iface" ]; then
            echo "[-] Error: Cannot use --mac without a default physical interface."
            exit 1
        fi
        echo "[+] Configuring MACVLAN network for PID $container_pid attached to $phys_iface..."
        
        # Create macvlan interface
        ip link add "$ns_iface" link "$phys_iface" type macvlan mode bridge
        ip link set "$ns_iface" netns "$container_pid"
        
        nsenter -t "$container_pid" -n ip addr add "$container_ip/24" dev "$ns_iface"
        nsenter -t "$container_pid" -n ip link set "$ns_iface" up
        nsenter -t "$container_pid" -n ip route add default via "$host_ip"
        
        echo "[*] Sandbox is running in MACVLAN mode. Direct network access established."
    else
        echo "[+] Configuring Bridged network for PID $container_pid..."
        
        # Create bridge if it doesn't exist
        if ! ip link show "$br_iface" &>/dev/null; then
            echo "[+] Creating bridge $br_iface for subnet $subnet_prefix/24..."
            ip link add "$br_iface" type bridge
            ip link set "$br_iface" up
        fi
        
        # Ensure bridge has the correct IP
        if ! ip addr show "$br_iface" | grep -q "inet $host_ip/"; then
            echo "[+] Assigning IP $host_ip to bridge $br_iface..."
            ip addr add "$host_ip/24" dev "$br_iface"
        fi
        ip link set "$br_iface" up

        # Disable reverse path filtering to allow local routing without NAT drops
        for sysctl_path in "/proc/sys/net/ipv4/conf/$br_iface/rp_filter" "/proc/sys/net/ipv4/conf/all/rp_filter"; do
            if [ -f "$sysctl_path" ]; then
                echo 0 > "$sysctl_path"
            fi
        done
        
        # Enable proxy_arp on bridge
        if [ -f "/proc/sys/net/ipv4/conf/$br_iface/proxy_arp" ]; then
            echo 1 > "/proc/sys/net/ipv4/conf/$br_iface/proxy_arp"
        fi

        # Enable IP forwarding globally
        sysctl -w net.ipv4.ip_forward=1 >/dev/null

        ip link add "$host_iface" type veth peer name "$ns_iface"
        ip link set "$host_iface" master "$br_iface"
        ip link set "$host_iface" up
        
        ip link set "$ns_iface" netns "$container_pid"
        
        nsenter -t "$container_pid" -n ip addr add "$container_ip/24" dev "$ns_iface"
        nsenter -t "$container_pid" -n ip link set "$ns_iface" up
        nsenter -t "$container_pid" -n ip route add default via "$host_ip"
        
        # Setup NAT and Forwarding
        if [ -n "$phys_iface" ]; then
            echo "[+] Enabling NAT (MASQUERADE) on $phys_iface for $subnet_prefix/24..."
            iptables -t nat -D POSTROUTING -s "$subnet_prefix/24" -o "$phys_iface" -j MASQUERADE 2>/dev/null || true
            iptables -t nat -I POSTROUTING 1 -s "$subnet_prefix/24" -o "$phys_iface" -j MASQUERADE
        else
            echo "[!] No default physical interface found. Internet access may be limited."
        fi
        
        # Forwarding rules - Force insert at top
        iptables -D FORWARD -s "$subnet_prefix/24" -j ACCEPT 2>/dev/null || true
        iptables -I FORWARD 1 -s "$subnet_prefix/24" -j ACCEPT
        
        iptables -D FORWARD -d "$subnet_prefix/24" -j ACCEPT 2>/dev/null || true
        iptables -I FORWARD 1 -d "$subnet_prefix/24" -j ACCEPT
        
        iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
        iptables -I FORWARD 1 -m state --state RELATED,ESTABLISHED -j ACCEPT
        
        # Handle firewalld if active
        if command -v firewall-cmd &>/dev/null && systemctl is-active firewalld &>/dev/null; then
            firewall-cmd --zone=trusted --add-interface="$br_iface" >/dev/null 2>&1 || true
        fi
    fi

    # Handle ufw if active
    if command -v ufw &>/dev/null && systemctl is-active ufw &>/dev/null; then
        ufw allow in on "$br_iface" >/dev/null 2>&1 || true
        ufw allow out on "$br_iface" >/dev/null 2>&1 || true
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
    
    local ip=$(cat "$STATE_DIR/$name.ip" 2>/dev/null || echo "unknown")

    # Build a temporary rcfile with a banner and custom prompt
    local rcfile
    rcfile=$(mktemp /tmp/rb-sensor-rc-XXXXXX)
    cat > "$rcfile" << BANNER
export PS1='\[\e[1;33m\]redborder-sensor[$name]\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]# '

echo ""
echo -e "\e[1;36m╔══════════════════════════════════════════════════════╗\e[0m"
echo -e "\e[1;36m║       Redborder Sensor Debug Shell                  ║\e[0m"
echo -e "\e[1;36m╚══════════════════════════════════════════════════════╝\e[0m"
echo ""
echo -e "  \e[1mSensor name:\e[0m  $name"
echo -e "  \e[1mSensor PID:\e[0m   $pid"
echo -e "  \e[1mSensor IP:\e[0m    $ip"
echo ""
echo -e "\e[1;33m  ⚠ DISTROLESS CONTAINER\e[0m"
echo -e "  You are using the \e[1mHOST filesystem\e[0m."
echo -e "  The container has no shell or utilities inside."
echo ""
echo -e "\e[1;32m  Active namespaces entered:\e[0m"
echo -e "   -n  Network  →  container IP/routes ($ip)"
echo -e "   -p  PID      →  container process tree"
echo -e "   -u  UTS      →  container hostname ($name)"
echo -e "   -i  IPC      →  container IPC"
echo -e "   (mount namespace: private, /proc remounted → ps shows only container PIDs)"
echo ""
echo -e "\e[1;32m  Running processes inside container:\e[0m"
ps --ppid "$pid" -o pid,comm,args --no-headers 2>/dev/null | sed 's/^/   /' || echo "   (none visible)"
echo ""
echo -e "\e[1;32m  Useful debug commands:\e[0m"
echo -e "   ip addr              →  show container network interfaces"
echo -e "   ip route             →  show container routing table"
echo -e "   ss -tulnp            →  show container listening ports"
echo -e "   tcpdump -i any       →  capture container traffic"
echo -e "   ps aux               →  list container processes"
echo -e "   kill -9 <pid>        →  terminate a container process"
echo ""
echo -e "  Type \e[1mexit\e[0m to leave the debug shell."
echo ""
BANNER

    # The stored PID is the 'unshare -p' process, which still lives in the HOST PID namespace.
    # (unshare -p creates a new namespace for its *children*, not itself.)
    # The actual container PID 1 (tini) is its first child and IS inside the container PID namespace.
    # We must nsenter -p into tini's PID, otherwise we enter the host PID namespace and
    # /proc (even if remounted) will show all host processes.
    local ns_pid
    ns_pid=$(pgrep -P "$pid" | head -n 1)
    [ -z "$ns_pid" ] && ns_pid="$pid"

    # Enter container namespaces: -n network, -p PID (via inner tini PID), -u UTS, -i IPC.
    # No -m: don't enter the container rootfs — host tools (bash, tcpdump, etc.) stay available.
    # Create a new private mount namespace and remount /proc scoped to the container PID namespace
    # so that ps/top only show container processes.
    nsenter -t "$ns_pid" -n -p -u -i \
        unshare --mount --propagation private \
        /bin/bash -c "mount -t proc proc /proc && exec /usr/bin/env -i \
SENSOR_NAME=\"$name\" \
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
TERM=\"$TERM\" \
/bin/bash --rcfile \"$rcfile\""
    rm -f "$rcfile"
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
        # No -m: binary is resolved from HOST filesystem (e.g. /sensor-data/ bind-mounted path)
        # -n/-p/-u/-i: inject into container namespaces without entering its stripped rootfs
        nsenter -t "$pid" -n -p -u -i \
            /usr/bin/env -i SENSOR_NAME="$name" PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin TERM="$TERM" \
            "${cmd[@]}" >> "$STATE_DIR/$name.log" 2>&1 &
    else
        nsenter -t "$pid" -n -p -u -i \
            /usr/bin/env -i SENSOR_NAME="$name" PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin TERM="$TERM" \
            "${cmd[@]}"
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
        if [ -f "$d/mac" ]; then
            [ "$(cat "$d/mac")" == "1" ] && start_args+=("--mac")
        fi

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
    __complete)
        # Hidden command for bash completion
        case "$2" in
            commands)
                echo "start stop list stats logs exec shell restore"
                ;;
            types)
                echo "ips snmp ipmi redfish webproxy telemetry sflow webserver"
                ;;
            running)
                for f in "$STATE_DIR"/*.pid; do
                    [ -e "$f" ] || continue
                    basename "$f" .pid
                done
                ;;
        esac
        ;;
    *)
        echo "Usage: $0 {start|stop|list|stats|logs|exec|shell|restore} [name]"
        echo ""
        echo "Commands:"
        echo "  start <name> [--ip <ip>] [--gw <gw>] [command|type]  Start a new sensor"
        echo "    Types: ips, snmp, ipmi, redfish, webproxy, telemetry, sflow, webserver"
        echo "    Note: Filenames in sensor-volume/ are automatically resolved to /sensor-data/"
        echo "  stop <name>                                          Stop a running sensor"
        echo "  restore                                              Restore all sensors from persistent config"
        echo "  list                                                 List all sensors"
        echo "  stats                                                Show real-time resource usage"
        echo "  logs <name> [-f]                                     Show sensor logs (-f to follow)"
        echo "  exec <name> [-d] <command>                           Run a command in a running sensor (-d for background)"
        echo "  shell <name>                                         Enter sensor shell"
        exit 1
        ;;
esac
