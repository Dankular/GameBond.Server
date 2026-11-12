#!/bin/bash
# Exercises the watchdog and update lock in server-probe.sh against a fake `docker`.
# No Docker daemon is needed:  bash tools/test-probe.sh
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/release" "$T/state"
export FAKE="$T/fake"; mkdir -p "$FAKE"
cat > "$T/bin/docker" <<'DOCKER'
#!/bin/bash
# state file holds "<status>|<health>"; `compose up` counts a recreate and applies $FAKE/after.
case "$1" in
  inspect) cat "$FAKE/state" 2>/dev/null || exit 1 ;;
  exec)    case "$(cat "$FAKE/state" 2>/dev/null)" in running\|*) exit 0 ;; *) exit 1 ;; esac ;;
  compose) echo x >> "$FAKE/recreates"; [ -e "$FAKE/after" ] && cp "$FAKE/after" "$FAKE/state" ;;
  pull)    exit 0 ;;
esac
DOCKER
chmod +x "$T/bin/docker"
export PATH="$T/bin:$PATH"
export GAMEBOND_PROBE_STATE="$T/state" GAMEBOND_PROBE_LOCK="$T/lock" GAMEBOND_PROBE_SOURCE_ONLY=1
echo "GAMEBOND_IMAGE=img:old" > "$T/release/deploy.env"
# shellcheck disable=SC1090
source "$HERE/server-probe.sh"
RELEASE="$T/release"; ENVFILE="$RELEASE/deploy.env"; READY_TRIES=2

fail=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got '$2', want '$3'"; fail=1; fi; }
recreates() { if [ -e "$FAKE/recreates" ]; then wc -l < "$FAKE/recreates"; else echo 0; fi; }
reset() { rm -f "$FAKE/recreates" "$FAKE/after" "$T/state/"{strikes,restarts,hold,watchdog-gave-up}; }
log() { :; }

reset; echo "running|healthy" > "$FAKE/state"
for _ in 1 2 3 4; do watchdog_check; done
check "healthy container is left alone" "$(recreates)" 0

reset; echo "exited|" > "$FAKE/state"; echo "running|healthy" > "$FAKE/after"
watchdog_check; watchdog_check
check "two strikes do not restart" "$(recreates)" 0
watchdog_check
check "third strike recreates" "$(recreates)" 1
check "container is up afterwards" "$(cat "$FAKE/state")" "running|healthy"
watchdog_check
check "no further action once healthy" "$(recreates)" 1

reset; echo "running|unhealthy" > "$FAKE/state"; echo "running|healthy" > "$FAKE/after"
for _ in 1 2 3; do watchdog_check; done
check "unhealthy container is recreated" "$(recreates)" 1

reset; echo "running|starting" > "$FAKE/state"
for _ in 1 2 3 4 5; do watchdog_check; done
check "a starting container is not restarted" "$(recreates)" 0

reset; echo "exited|" > "$FAKE/state"; touch "$T/state/hold"
for _ in 1 2 3 4; do watchdog_check; done
check "hold file pauses the watchdog" "$(recreates)" 0

reset; echo "exited|" > "$FAKE/state"
( exec 8>"$T/lock"; flock -n 8; sleep 3 ) & holder=$!; sleep 0.3
for _ in 1 2 3 4; do watchdog_check; done
check "watchdog stays out while an update holds the lock" "$(recreates)" 0
wait $holder

reset; echo "exited|" > "$FAKE/state"   # recreate never helps
for _ in $(seq 1 15); do watchdog_check; done
check "restarts are capped inside the window" "$(recreates)" 3
check "gives up visibly" "$([ -e "$T/state/watchdog-gave-up" ] && echo yes)" yes

reset; echo "running|healthy" > "$FAKE/state"
update_to abc123 >/dev/null 2>&1
check "update_to switched the image" "$(current_image)" "ghcr.io/dankular/gamebond-server:abc123"
if flock -n "$T/lock" true; then echo "ok   update lock is released after an update"; else echo "FAIL update lock still held"; fail=1; fi

exit $fail
