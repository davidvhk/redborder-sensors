#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

# Configuration
NAME="default"
INSIDE_NS=0
INSIDE_USER_NS=0

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
        --inside-user-ns)
            INSIDE_USER_NS=1
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

# 1. Ensure the script is run as root (in parent process)
if [ "$INSIDE_USER_NS" -eq 0 ] && [ "$EUID" -ne 0 ]; then
    echo "[-] This script requires root privileges. Please run with sudo."
    exit 1
fi

# =====================================================================
# PHASE 3: Inside User, Mount, and PID Namespaces (Mapped Container Root)
# =====================================================================
if [ "$INSIDE_USER_NS" -eq 1 ]; then
    cd "$CONTAINER_DIR"
    export PATH=/bin:/sbin

    INIT_CMD=""
    if [ -f "./bin/tini" ]; then
        INIT_CMD="/bin/tini"
    fi

    if [ $# -gt 0 ]; then
        echo "[+] Executing command: $@"
        if [ -n "$INIT_CMD" ]; then
            exec "$BUSYBOX" setpriv --no-new-privs "$BUSYBOX" chroot . "$INIT_CMD" env SENSOR_NAME="$NAME" "$@"
        else
            exec "$BUSYBOX" setpriv --no-new-privs "$BUSYBOX" chroot . env SENSOR_NAME="$NAME" "$@"
        fi
    else
        if [ -n "$INIT_CMD" ]; then
            exec "$BUSYBOX" setpriv --no-new-privs "$BUSYBOX" chroot . "$INIT_CMD" env SENSOR_NAME="$NAME" /bin/sh --login
        else
            exec "$BUSYBOX" setpriv --no-new-privs "$BUSYBOX" chroot . env SENSOR_NAME="$NAME" /bin/sh --login
        fi
    fi
    exit 0
fi

# =====================================================================
# PHASE 1 & 2: Host Side & Setup (Run as Host Root)
# =====================================================================

# FIX: Create the host shared directory BEFORE unsharing namespaces
if [ ! -d "$HOST_SHARED_DIR" ]; then
    echo "[+] Creating shared directory on host: $HOST_SHARED_DIR"
    mkdir -p "$HOST_SHARED_DIR"
    chmod 777 "$HOST_SHARED_DIR"
fi

# Stage the BusyBox binary on the host if not already present
if [ ! -f "$BUSYBOX" ]; then
    echo "[+] Downloading static BusyBox binary..."
    wget -q "$BUSYBOX_URL" -O "$BUSYBOX"
    chmod +x "$BUSYBOX"
fi

# Setup cgroup resource limits on the host (run as host root before unsharing namespaces)
if [ "$INSIDE_NS" -eq 0 ] && [ "$INSIDE_USER_NS" -eq 0 ]; then
    cg_dir="/sys/fs/cgroup/redborder-sensors/$NAME"
    if [ -d "/sys/fs/cgroup" ]; then
        echo "[+] Setting up cgroup v2 resource limits for '$NAME'..."
        # Enable memory and pids controllers in parent cgroups if possible
        echo "+memory +pids" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
        mkdir -p "/sys/fs/cgroup/redborder-sensors"
        echo "+memory +pids" > /sys/fs/cgroup/redborder-sensors/cgroup.subtree_control 2>/dev/null || true
        
        # Create sandbox cgroup
        mkdir -p "$cg_dir"
        
        # Set limits: 128MB RAM, 50 processes/threads
        echo 134217728 > "$cg_dir/memory.max" 2>/dev/null || true
        echo 50 > "$cg_dir/pids.max" 2>/dev/null || true
        
        # Assign this process to the cgroup
        echo "$$" > "$cg_dir/cgroup.procs" 2>/dev/null || true
    fi
fi

# Phase 1: Unshare mount, network, UTS, IPC, cgroup namespaces
if [ "$INSIDE_NS" -eq 0 ]; then
    echo "[+] Spawning isolated Mount, Network, UTS, IPC, and Cgroup namespaces for '$NAME'..."
    exec unshare -C -m -n -u -i -f "$0" --inside-ns --name="$NAME" "$@"
fi

# Phase 2: Setup Container Directory Layout & Mounts (Inside Mount/Network/UTS/IPC/Cgroup Netns)
# Ensure mount propagation is private in this mount namespace to allow pivot_root later
/bin/mount --make-rprivate /

echo "[+] Preparing sterile root filesystem in $CONTAINER_DIR..."
mkdir -p "$CONTAINER_DIR"
mount -t tmpfs -o nosuid,nodev none "$CONTAINER_DIR"
/bin/mount --make-private "$CONTAINER_DIR"

# Create minimal directory layout
mkdir -p "$CONTAINER_DIR"/{bin,sbin,proc,sys,dev,root,old_root,sensor-data}

# Copy the staged busybox into the container root
cp "$BUSYBOX" "$CONTAINER_DIR/bin/busybox"

# Copy the tini binary into the container root
if [ -f "$HOST_SHARED_DIR/tini" ]; then
    echo "[+] Copying tini binary into container root..."
    cp "$HOST_SHARED_DIR/tini" "$CONTAINER_DIR/bin/tini"
    chmod +x "$CONTAINER_DIR/bin/tini"
fi

echo "[+] Populating container with relative BusyBox symlinks..."
cd "$CONTAINER_DIR/bin"
for cmd in $(./busybox --list); do
    ln -sf busybox "$cmd"
done
cd "$CONTAINER_DIR"

echo "[+] Mounting isolated kernel filesystems..."
# Mount proc and sysfs read-only directly!
mount -t proc -o ro,nosuid,nodev,noexec proc "$CONTAINER_DIR/proc"
mount -t sysfs -o ro,nosuid,nodev,noexec sysfs "$CONTAINER_DIR/sys"

# Mount a private tmpfs on dev and create standard device nodes to avoid host devtmpfs exposures
echo "[+] Creating isolated dev filesystem..."
if mount -t tmpfs -o nosuid,noexec,mode=755 none "$CONTAINER_DIR/dev"; then
    if mknod -m 666 "$CONTAINER_DIR/dev/null" c 1 3 2>/dev/null && \
       mknod -m 666 "$CONTAINER_DIR/dev/tty" c 5 0 2>/dev/null && \
       mknod -m 666 "$CONTAINER_DIR/dev/urandom" c 1 9 2>/dev/null && \
       mknod -m 666 "$CONTAINER_DIR/dev/random" c 1 8 2>/dev/null; then
        echo "[+] Successfully created device nodes inside dev tmpfs."
    else
        echo "[!] mknod not permitted, falling back to bind mounts..."
        umount "$CONTAINER_DIR/dev" || true
        touch "$CONTAINER_DIR/dev/null" "$CONTAINER_DIR/dev/tty" "$CONTAINER_DIR/dev/urandom" "$CONTAINER_DIR/dev/random"
        mount --bind /dev/null "$CONTAINER_DIR/dev/null"
        mount --bind /dev/tty "$CONTAINER_DIR/dev/tty"
        mount --bind /dev/urandom "$CONTAINER_DIR/dev/urandom"
        mount --bind /dev/random "$CONTAINER_DIR/dev/random"
    fi
else
    echo "[!] Failed to mount dev tmpfs, falling back to bind mounts..."
    touch "$CONTAINER_DIR/dev/null" "$CONTAINER_DIR/dev/tty" "$CONTAINER_DIR/dev/urandom" "$CONTAINER_DIR/dev/random"
    mount --bind /dev/null "$CONTAINER_DIR/dev/null"
    mount --bind /dev/tty "$CONTAINER_DIR/dev/tty"
    mount --bind /dev/urandom "$CONTAINER_DIR/dev/urandom"
    mount --bind /dev/random "$CONTAINER_DIR/dev/random"
fi

echo "[+] Binding host shared directory into container..."
mount --bind "$HOST_SHARED_DIR" "$CONTAINER_DIR/sensor-data"
mount -o remount,bind,nosuid,nodev,noexec,nosymfollow "$CONTAINER_DIR/sensor-data"

echo "[+] Define dns server ${DNS}"
mkdir -p "$CONTAINER_DIR/etc"
echo "nameserver ${DNS}" > "$CONTAINER_DIR/etc/resolv.conf"

echo "[+] Bringing up the loopback network interface..."
"$BUSYBOX" ip link set lo up

echo "[+] Allowing unprivileged port binding..."
if [ -f "/proc/sys/net/ipv4/ip_unprivileged_port_start" ]; then
    echo 0 > /proc/sys/net/ipv4/ip_unprivileged_port_start
fi

echo "[+] Setting hostname to '$NAME'..."
"$BUSYBOX" hostname "$NAME"

# Wait for network plumbing (veth-ns)
# Wait up to 5 seconds for the host to configure the network
for i in $("$BUSYBOX" seq 1 50); do
    if "$BUSYBOX" ip addr show veth-ns 2>/dev/null | "$BUSYBOX" grep -q "inet "; then
        break
    fi
    "$BUSYBOX" sleep 0.1
done

# Create a nice prompt and greeting in /etc/profile inside the container root
cat <<'EOF' > "$CONTAINER_DIR/etc/profile"
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

# Detect and handle binaries running from /sensor-data
# If the command starts with /sensor-data/, copy it to /bin inside container to allow mounting /sensor-data as noexec
if [ $# -gt 0 ]; then
    TARGET_CMD="$1"
    if [[ "$TARGET_CMD" == /sensor-data/* ]]; then
        cmd_base=$(basename "$TARGET_CMD")
        if [ -f "$CONTAINER_DIR$TARGET_CMD" ]; then
            echo "[+] Copying agent binary $cmd_base to container /bin for security..."
            cp "$CONTAINER_DIR$TARGET_CMD" "$CONTAINER_DIR/bin/$cmd_base"
            chmod +x "$CONTAINER_DIR/bin/$cmd_base"
            # Rewrite first argument to use the copy in /bin
            set -- "/bin/$cmd_base" "${@:2}"
        fi
    fi
fi

# Determine the target UID and GID for user namespace mapping
target_uid=${SUDO_UID:-2005}
target_gid=${SUDO_GID:-2005}
if [ "$target_uid" -eq 0 ]; then
    dir_owner=$(stat -c '%u' "$HOST_SHARED_DIR" 2>/dev/null || echo 1000)
    dir_group=$(stat -c '%g' "$HOST_SHARED_DIR" 2>/dev/null || echo 1000)
    if [ "$dir_owner" -ne 0 ]; then
        target_uid="$dir_owner"
        target_gid="$dir_group"
    else
        target_uid=1000
        target_gid=1000
    fi
fi

# Remount container root filesystem read-only for security hardening
echo "[+] Remounting root filesystem read-only..."
mount -o remount,ro "$CONTAINER_DIR" 2>/dev/null || echo "[!] Warning: Failed to remount root filesystem read-only. Continuing..."

# Transition to Phase 3:
# 1. chpst switches to the target unprivileged UID/GID on the host
# 2. unshare creates a new user, mount, and PID namespace (mapping unprivileged host user to container root)
# 3. Executes /var/lib/redborder-sensors/bin/sensor-bbox.sh with --inside-user-ns flag
exec "$BUSYBOX" chpst -u "$target_uid:$target_gid" \
    "$BUSYBOX" unshare -m -p -f -U -r \
    /var/lib/redborder-sensors/bin/sensor-bbox.sh --inside-user-ns --inside-ns --name="$NAME" "$@"
