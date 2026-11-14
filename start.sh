#!/bin/sh
# Splash Manager start/stop script for EngineX OS mod system
# Handles architecture detection, PID safety, and backup/restore.

MOD_DIR="$(cd "$(dirname "$0")" && pwd)"
STATE_DIR="${ENGINEX_MOD_STATE:-/data/enginex/mods-state}/splash-manager"
PID_FILE="$STATE_DIR/server.pid"
LOG_FILE="$STATE_DIR/server.log"

mkdir -p "$STATE_DIR"

# Check if a PID actually belongs to our server
is_our_process() {
    pid="$1"
    [ -z "$pid" ] && return 1
    [ ! -d "/proc/$pid" ] && return 1
    # verify cmdline contains splash-server
    cmdline="$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')"
    case "$cmdline" in
        *splash-server*) return 0 ;;
    esac
    return 1
}

stop_server() {
    if [ -f "$PID_FILE" ]; then
        pid="$(cat "$PID_FILE")"
        if is_our_process "$pid"; then
            kill "$pid" 2>/dev/null
            # wait briefly for clean shutdown
            i=0; while [ $i -lt 10 ] && is_our_process "$pid"; do
                sleep 0.2; i=$((i+1))
            done
        fi
        rm -f "$PID_FILE"
    fi
}

case "$1" in
    start)
        stop_server

        # select binary for architecture
        case "$(uname -m)" in
            aarch64|arm64) BIN="$MOD_DIR/splash-server-aarch64" ;;
            arm*|armv7*)   BIN="$MOD_DIR/splash-server-armhf" ;;
            *)
                echo "Unsupported architecture: $(uname -m)" >&2
                exit 1
                ;;
        esac

        # ensure executable bit (Web Console install sets 0644)
        chmod 755 "$BIN" 2>/dev/null

        # start the server
        nohup "$BIN" >"$LOG_FILE" 2>&1 &
        SERVER_PID=$!
        echo "$SERVER_PID" > "$PID_FILE"

        # verify it actually started
        sleep 0.5
        if is_our_process "$SERVER_PID"; then
            echo "Splash Manager started (PID $SERVER_PID, port 8081)"
            exit 0
        else
            echo "ERROR: splash-server failed to start. Check $LOG_FILE" >&2
            rm -f "$PID_FILE"
            exit 1
        fi
        ;;
    stop)
        stop_server
        echo "Splash Manager stopped"
        exit 0
        ;;
    *)
        echo "Usage: $0 {start|stop}" >&2
        exit 1
        ;;
esac
