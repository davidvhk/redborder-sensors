#!/usr/bin/env bash

# sensor-chaos.sh - Inject failures into redborder sensors
# Usage: sudo ./sensor-chaos.sh <command> <name> [args]

STATE_DIR="/tmp/redborder-sensors"
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

if [ "$EUID" -ne 0 ]; then
    echo "[-] This script requires root privileges. Please run with sudo."
    exit 1
fi

# Check for required tools
for tool in tc iptables ip; do
    if ! command -v "$tool" &>/dev/null; then
        echo "[-] Error: Required tool '$tool' not found. Please install it (e.g., sudo dnf install iproute iptables)."
        exit 1
    fi
done

BIN_DIR="/var/lib/redborder-sensors/bin"
BUSYBOX="$BIN_DIR/busybox"

function get_pid() {
    local name=$1
    if [ -f "$STATE_DIR/$name.pid" ]; then
        cat "$STATE_DIR/$name.pid"
    fi
}

function get_ip() {
    local name=$1
    if [ -f "$STATE_DIR/$name.ip" ]; then
        cat "$STATE_DIR/$name.ip"
    fi
}

function check_sandbox() {
    local name=$1
    local pid=$(get_pid "$name")
    if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
        echo "[-] Sandbox '$name' is not running."
        exit 1
    fi
    echo "$pid"
}

function cmd_loss() {
    local name=$1
    local percent=$2
    if [ -z "$percent" ]; then
        echo "Usage: $0 loss <name> <percent>"
        exit 1
    fi
    check_sandbox "$name" >/dev/null
    local dev="veth-$name"
    echo "[+] Injecting $percent% packet loss on $dev..."
    tc qdisc del dev "$dev" root 2>/dev/null
    tc qdisc add dev "$dev" root netem loss "$percent%"
}

function cmd_delay() {
    local name=$1
    local delay=$2
    if [ -z "$delay" ]; then
        echo "Usage: $0 delay <name> <ms>"
        exit 1
    fi
    check_sandbox "$name" >/dev/null
    local dev="veth-$name"
    echo "[+] Injecting ${delay}ms delay on $dev..."
    tc qdisc del dev "$dev" root 2>/dev/null
    tc qdisc add dev "$dev" root netem delay "${delay}ms"
}

function cmd_down() {
    local name=$1
    local pid=$(check_sandbox "$name")
    echo "[+] Bringing down network interface inside '$name'..."
    "$BUSYBOX" nsenter -t "$pid" -n ip link set veth-ns down
}

function cmd_up() {
    local name=$1
    local pid=$(check_sandbox "$name")
    local ip=$(get_ip "$name")
    if [ -z "$ip" ]; then
        echo "[-] Could not determine IP for sensor '$name'."
        exit 1
    fi
    local gw=$(echo "$ip" | sed 's/\.[0-9]*$/\.1/')
    echo "[+] Bringing up network interface inside '$name' and restoring config (IP: $ip, GW: $gw)..."
    "$BUSYBOX" nsenter -t "$pid" -n ip link set veth-ns up
    "$BUSYBOX" nsenter -t "$pid" -n ip addr add "$ip/24" dev veth-ns 2>/dev/null || true
    "$BUSYBOX" nsenter -t "$pid" -n ip route add default via "$gw" 2>/dev/null || true
}

function cmd_block() {
    local name=$1
    local port=$2
    local proto=${3:-udp}
    if [ -z "$port" ]; then
        echo "Usage: $0 block <name> <port> [tcp|udp]"
        exit 1
    fi
    local ip=$(get_ip "$name")
    echo "[+] Blocking $proto port $port for sensor '$name' ($ip)..."
    iptables -I OUTPUT -d "$ip" -p "$proto" --dport "$port" -m comment --comment "sensor-chaos:$name" -j DROP
    iptables -I INPUT -s "$ip" -p "$proto" --sport "$port" -m comment --comment "sensor-chaos:$name" -j DROP
}

function cmd_unblock() {
    local name=$1
    local port=$2
    local proto=${3:-udp}
    local ip=$(get_ip "$name")
    echo "[+] Unblocking $proto port $port for sensor '$name'..."
    # Delete by rule specification to be precise
    iptables -D OUTPUT -d "$ip" -p "$proto" --dport "$port" -m comment --comment "sensor-chaos:$name" -j DROP 2>/dev/null
    iptables -D INPUT -s "$ip" -p "$proto" --sport "$port" -m comment --comment "sensor-chaos:$name" -j DROP 2>/dev/null
}

function cmd_kill() {
    local name=$1
    local pid=$(check_sandbox "$name")
    echo "[+] Killing main process (PID $pid) in sensor '$name'..."
    kill -9 "$pid"
}

function cmd_clear() {
    local name=$1
    local dev="veth-$name"
    local ip=$(get_ip "$name")
    echo "[+] Clearing all impairments for sensor '$name'..."
    tc qdisc del dev "$dev" root 2>/dev/null
    
    # Clear iptables rules with our comment
    # We do this in a loop because there might be multiple rules
    while iptables -D OUTPUT -m comment --comment "sensor-chaos:$name" -j DROP 2>/dev/null; do :; done
    while iptables -D INPUT -m comment --comment "sensor-chaos:$name" -j DROP 2>/dev/null; do :; done
    
    # Also ensure interface is up
    local pid=$(get_pid "$name")
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        "$BUSYBOX" nsenter -t "$pid" -n ip link set veth-ns up 2>/dev/null
    fi
}

function cmd_status() {
    local name=$1
    local pid=$(get_pid "$name")
    local ip=$(get_ip "$name")
    local dev="veth-$name"
    
    echo "Chaos Status for Sandbox: $name"
    echo "--------------------------------"
    if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
        echo "Status: STOPPED"
        return
    fi
    echo "Status: RUNNING (PID $pid, IP $ip)"
    
    echo -n "Interface: "
    "$BUSYBOX" nsenter -t "$pid" -n ip link show veth-ns | grep -q "UP" && echo "UP" || echo "DOWN"
    
    echo "Network Impairments (tc):"
    tc qdisc show dev "$dev" | grep -v "noqueue" || echo "  None"
    
    echo "Blocked Ports (iptables):"
    local rules=$(iptables -S | grep "sensor-chaos:$name")
    if [ -n "$rules" ]; then
        echo "$rules" | sed 's/-A/- /'
    else
        echo "  None"
    fi
}

case "$1" in
    loss)   shift; cmd_loss "$@" ;;
    delay)  shift; cmd_delay "$@" ;;
    down)   shift; cmd_down "$@" ;;
    up)     shift; cmd_up "$@" ;;
    block)  shift; cmd_block "$@" ;;
    unblock) shift; cmd_unblock "$@" ;;
    kill)   shift; cmd_kill "$@" ;;
    clear)  shift; cmd_clear "$@" ;;
    status) shift; cmd_status "$@" ;;
    *)
        echo "Usage: $0 {loss|delay|down|up|block|unblock|kill|clear|status} <name> [args]"
        echo ""
        echo "Commands:"
        echo "  loss <name> <%>          Inject packet loss"
        echo "  delay <name> <ms>        Inject latency"
        echo "  down <name>              Bring interface DOWN inside sensor"
        echo "  up <name>                Bring interface UP inside sensor"
        echo "  block <name> <port>      Block a port (default UDP, e.g. 161 for SNMP)"
        echo "  unblock <name> <port>    Unblock a port"
        echo "  kill <name>              Kill the main sensor process"
        echo "  clear <name>             Clear all impairments"
        echo "  status <name>            Show current impairment status"
        exit 1
        ;;
esac
