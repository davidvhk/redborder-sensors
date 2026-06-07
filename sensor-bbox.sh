#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

# Configuration
NAME="default"
INSIDE_NS=0

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --name=*)
            NAME="${1#--name=}"
            shift
            ;;
        --inside-ns)
            INSIDE_NS=1
            shift
            ;;
        *)
            break
            ;;
    esac
done

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
CONTAINER_DIR="/tmp/redborder-sensor-$NAME"
HOST_SHARED_DIR="${HOST_SHARED_DIR:-$SCRIPT_DIR/sensor-volume}" 
DNS="1.1.1.1"
BUSYBOX_URL="https://busybox.net/downloads/binaries/1.35.0-x86_64-linux-musl/busybox"
BIN_DIR="/var/lib/redborder-sensors/bin"
mkdir -p "$BIN_DIR"
BUSYBOX="$BIN_DIR/busybox"

# 1. Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "[-] This script requires root privileges. Please run with sudo."
    exit 1
fi

# FIX: Create the host shared directory BEFORE unsharing namespaces
if [ ! -d "$HOST_SHARED_DIR" ]; then
    echo "[+] Creating shared directory on host: $HOST_SHARED_DIR"
    mkdir -p "$HOST_SHARED_DIR"
    # Ensure regular users can read/write to it easily
    chmod 777 "$HOST_SHARED_DIR"
fi

# 2. Stage the BusyBox binary on the host if not already present
if [ ! -f "$BUSYBOX" ]; then
    echo "[+] Downloading static BusyBox binary..."
    wget -q "$BUSYBOX_URL" -O "$BUSYBOX"
    chmod +x "$BUSYBOX"
fi

# 3. Handle the namespace unsharing and pivot setup
if [ "$INSIDE_NS" -eq 0 ]; then
	    echo "[+] Spawning isolated Mount, Network, and PID namespaces for '$NAME'..."
	        exec unshare -m -n -p -f "$0" --inside-ns --name="$NAME" "$@"
fi

# --- EVERYTHING BELOW EXECUTES INSIDE THE ISOLATED NAMESPACES ---

echo "[+] Preparing sterile root filesystem in $CONTAINER_DIR..."
mkdir -p "$CONTAINER_DIR"
mount -t tmpfs none "$CONTAINER_DIR"

# Create minimal directory layout (including sensor-data)
mkdir -p "$CONTAINER_DIR"/{bin,sbin,proc,sys,dev,root,old_root,sensor-data}

# Copy the staged busybox into the container root
cp "$BUSYBOX" "$CONTAINER_DIR/bin/busybox"

echo "[+] Populating container with relative BusyBox symlinks..."
cd "$CONTAINER_DIR/bin"
for cmd in $(./busybox --list); do
    ln -sf busybox "$cmd"
done
cd "$CONTAINER_DIR"

    echo "[+] Mounting isolated kernel filesystems (before pivot)..."
    mount -t proc proc "$CONTAINER_DIR/proc"
    mount -t sysfs sysfs "$CONTAINER_DIR/sys"

    # Bind mount the critical device nodes from the host
    touch "$CONTAINER_DIR/dev/null" "$CONTAINER_DIR/dev/tty" "$CONTAINER_DIR/dev/urandom" "$CONTAINER_DIR/dev/random"
    mount --bind /dev/null "$CONTAINER_DIR/dev/null"
    mount --bind /dev/tty "$CONTAINER_DIR/dev/tty"
    mount --bind /dev/urandom "$CONTAINER_DIR/dev/urandom"
    mount --bind /dev/random "$CONTAINER_DIR/dev/random"

    echo "[+] Binding host shared directory into container..."
    mount --bind "$HOST_SHARED_DIR" "$CONTAINER_DIR/sensor-data"

    echo "[+] Define dns server ${DNS}"
    mkdir -p "$CONTAINER_DIR/etc"
    echo "nameserver ${DNS}" > "$CONTAINER_DIR/etc/resolv.conf"

    echo "[+] Pivoting root filesystem..."
    pivot_root . old_root
    cd /

    echo "[+] Detaching host filesystem layout..."
    /bin/busybox umount -l /old_root

    echo "[+] Bringing up the loopback network interface..."
    # Use explicit busybox path because host /bin/ip is gone and /bin/ip (link) might not be ready
    /bin/busybox ip link set lo up

    echo "[+] Waiting for network plumbing (veth-ns)..."
    # Wait up to 5 seconds for the host to configure the network
    for i in $(/bin/busybox seq 1 50); do
        if /bin/busybox ip addr show veth-ns 2>/dev/null | /bin/busybox grep -q "inet "; then
            break
        fi
        /bin/busybox sleep 0.1
    done

    # Set internal PATH so subsequent commands (like cat) work
    export PATH=/bin:/sbin

    # Create a nice prompt and greeting in /etc/profile
    cat <<'EOF' > /etc/profile
export PATH=/bin:/sbin
export PS1='redborder-sensor:[\w]# '

echo -e "\n===================================================="
echo " Welcome to your redborder sensor!"
echo "----------------------------------------------------"
echo " - Isolated: Network, PID, Mounts"
echo " - Binaries: Check '/bin' and '/sbin'"
echo " - Shared:   '/sensor-data' (maps to host sensor-volume/)"
echo "----------------------------------------------------"
echo " To run the telemetry agent:"
echo " # /sensor-data/telemetry-agent -mode syslog"
echo "===================================================="
echo ""
EOF

    if [ $# -gt 0 ]; then
        echo "[+] Executing command: $@"
        # BusyBox env doesn't support '--'
        exec env SENSOR_NAME="$NAME" "$@"
    else
        exec env SENSOR_NAME="$NAME" /bin/sh --login
    fi
