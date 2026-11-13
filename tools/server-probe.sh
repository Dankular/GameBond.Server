#!/bin/bash
# gamebond-probe: runs on the VPS. Watches GitHub Actions for a newer successful "server-image"
# build of main and, when there is one, performs a clean update: pull the image, recreate the
# container, wait until it is really ready, and put the previous image back if it is not.
#
#   gamebond-probe            watch forever (the systemd service)
#   gamebond-probe update     check once and update if a newer build exists
#   gamebond-probe update SHA update to that commit's image (must already be built)
#
# While watching it also acts as a watchdog: when the container is exited, missing or reported
# unhealthy for WATCHDOG_STRIKES polls in a row it is recreated (at most WATCHDOG_MAX_RESTARTS
# times per WATCHDOG_WINDOW seconds, never during an update). `touch $STATE/hold` pauses the
# watchdog, for example while you stop the container on purpose.
set -u
REPO=Dankular/GameBond.Server
WORKFLOW=server-image.yml
IMAGE_REPO=ghcr.io/dankular/gamebond-server
RELEASE=/opt/gamebond/releases/native-live
ENVFILE=$RELEASE/deploy.env
CONTAINER=gamebond-native-1
STATE=${GAMEBOND_PROBE_STATE:-/var/lib/gamebond-probe}
LOCKFILE=${GAMEBOND_PROBE_LOCK:-/var/lock/gamebond-update}
WATCHDOG_STRIKES=${GAMEBOND_WATCHDOG_STRIKES:-3}
WATCHDOG_MAX_RESTARTS=${GAMEBOND_WATCHDOG_MAX_RESTARTS:-3}
WATCHDOG_WINDOW=${GAMEBOND_WATCHDOG_WINDOW:-600}
INTERVAL=${GAMEBOND_PROBE_INTERVAL:-10}
READY_TRIES=300   # x 0.1 s
mkdir -p "$STATE"

log() { echo "$(date -Is) $*"; }

current_image() { sed -n 's/^GAMEBOND_IMAGE=//p' "$ENVFILE" | tail -1; }

ready() {
  docker exec "$CONTAINER" sh -c 'test -e /tmp/gamebond-ready && test -d /sys/class/net/gamebond0 && kill -0 "$(cat /tmp/gamebond.pid)"' 2>/dev/null
}

wait_ready() {
  local n=0
  until ready; do
    n=$((n + 1)); [ $n -ge $READY_TRIES ] && return 1
    sleep 0.1
  done
}

recreate() {
  ( cd "$RELEASE" && docker compose --env-file deploy.env up -d --no-build --force-recreate >/dev/null 2>&1 )
}

set_image() {
  if grep -q '^GAMEBOND_IMAGE=' "$ENVFILE"; then
    sed -i "s|^GAMEBOND_IMAGE=.*|GAMEBOND_IMAGE=$1|" "$ENVFILE"
  else
    echo "GAMEBOND_IMAGE=$1" >> "$ENVFILE"
  fi
}

# Latest successful build of main; prints the commit sha. 304 (nothing new) prints nothing.
# A conditional request that returns 304 does not count against GitHub's rate limit.
latest_build() {
  local url="https://api.github.com/repos/$REPO/actions/workflows/$WORKFLOW/runs?branch=main&status=success&per_page=1"
  local code
  code=$(curl -sS -m 15 -o "$STATE/body" -w '%{http_code}' -D "$STATE/headers" \
    -H "Accept: application/vnd.github+json" \
    ${ETAG:+-H "If-None-Match: $ETAG"} "$url") || return 1
  case "$code" in
    304) return 0 ;;
    200) ETAG=$(sed -n 's/^[Ee][Tt]ag: *//p' "$STATE/headers" | tr -d '\r' | head -1)
         sed -n 's/.*"head_sha": *"\([0-9a-f]\{40\}\)".*/\1/p' "$STATE/body" | head -1 ;;
    *)   log "github api returned $code"; return 1 ;;
  esac
}

# update_to serialises updates with a lock that is held only while one runs. (fd 9 used to stay
# open for the life of the watch loop, which kept the lock held after the first update.)
update_to() {
  local rc
  [ "$(current_image)" = "$IMAGE_REPO:$1" ] && return 0
  exec 9>"$LOCKFILE"
  flock -w 120 9 || { exec 9>&-; log "another update holds the lock"; return 1; }
  _update_to "$1"; rc=$?
  exec 9>&-
  return $rc
}

_update_to() {
  local sha=$1 want="$IMAGE_REPO:$1" prev
  prev=$(current_image)
  [ "$prev" = "$want" ] && return 0
  log "updating $prev -> $want"
  local t0=$SECONDS
  if ! docker pull -q "$want" >/dev/null; then log "pull failed; nothing changed"; return 1; fi
  # Tell connected clients first, so their UI shows "updating" rather than "down".
  docker exec "$CONTAINER" touch /tmp/gamebond-updating 2>/dev/null && sleep 1.5
  set_image "$want"
  recreate
  if wait_ready; then
    log "updated to $sha in $((SECONDS - t0)) s (container ready)"
    echo "$sha" > "$STATE/last-good"
    return 0
  fi
  log "new container did not become ready; rolling back to $prev"
  set_image "$prev"
  recreate
  if wait_ready; then log "rolled back, previous image is serving"; else log "ROLLBACK ALSO NOT READY: needs a human"; fi
  echo "$sha" > "$STATE/rejected"   # do not retry the same commit every interval
  return 1
}

check_once() {
  local sha
  sha=$(latest_build) || return 1
  [ -n "$sha" ] || return 0
  [ "$sha" = "$(cat "$STATE/rejected" 2>/dev/null)" ] && return 0
  update_to "$sha"
}

# container_state prints "<status>|<health>" ("missing|" if there is no such container).
container_state() {
  docker inspect -f '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$CONTAINER" 2>/dev/null || echo "missing|"
}

# watchdog_check runs once per poll. A recreate here is the same operation an update performs,
# so clients see an ordinary restart.
watchdog_check() {
  [ -e "$STATE/hold" ] && { echo 0 > "$STATE/strikes"; return 0; }
  local st status health strikes now recent
  # Never race an update: skip the check while one holds the lock.
  ( flock -n 8 ) 8>"$LOCKFILE" || return 0
  st=$(container_state); status=${st%%|*}; health=${st#*|}
  case "$status|$health" in
    "running|healthy"|"running|starting"|"running|") echo 0 > "$STATE/strikes"; rm -f "$STATE/watchdog-gave-up"; return 0 ;;
  esac
  strikes=$(( $(cat "$STATE/strikes" 2>/dev/null || echo 0) + 1 ))
  echo "$strikes" > "$STATE/strikes"
  log "watchdog: container is $status/${health:-no-health} (strike $strikes of $WATCHDOG_STRIKES)"
  [ "$strikes" -ge "$WATCHDOG_STRIKES" ] || return 0
  now=$(date +%s)
  # Keep only restart times inside the window.
  recent=$(awk -v n="$now" -v w="$WATCHDOG_WINDOW" '$1 > n - w' "$STATE/restarts" 2>/dev/null)
  if [ "$(printf '%s\n' "$recent" | grep -c .)" -ge "$WATCHDOG_MAX_RESTARTS" ]; then
    [ -e "$STATE/watchdog-gave-up" ] || log "watchdog: $WATCHDOG_MAX_RESTARTS restarts in ${WATCHDOG_WINDOW}s did not help; giving up until it recovers (needs a human)"
    touch "$STATE/watchdog-gave-up"; return 0
  fi
  printf '%s\n' "$recent" | grep . > "$STATE/restarts.new"; echo "$now" >> "$STATE/restarts.new"; mv "$STATE/restarts.new" "$STATE/restarts"
  echo 0 > "$STATE/strikes"
  log "watchdog: recreating $CONTAINER"
  recreate
  if wait_ready; then log "watchdog: container is ready again"; rm -f "$STATE/watchdog-gave-up"; else log "watchdog: container still not ready"; fi
}

# sync_forward keeps the reverse-proxy forwarding (tools/host-forward.sh, installed beside the release)
# pointed at the running container. Its rules are not persistent and the container address can change
# on every recreate, so the check runs each poll; it only acts when the rules are missing or stale.
FORWARD=${GAMEBOND_HOST_FORWARD:-/opt/gamebond/host-forward.sh}
sync_forward() {
  [ -x "$FORWARD" ] || return 0
  [ "$(container_state)" = "running|healthy" ] || return 0
  local ip
  ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER" 2>/dev/null)
  [ -n "$ip" ] || return 0
  if nft list table ip gamebond_exit 2>/dev/null | grep -q "dnat to $ip\$"      && iptables -S DOCKER-USER 2>/dev/null | grep -q -- "-d $ip/32 .*gamebond-reverse-forward"; then
    return 0
  fi
  if "$FORWARD" apply "$CONTAINER" >/dev/null 2>&1; then log "reverse forwarding applied for $CONTAINER ($ip)"
  else log "reverse forwarding could not be applied for $CONTAINER ($ip)"; fi
}

[ "${GAMEBOND_PROBE_SOURCE_ONLY:-0}" = 1 ] && return 0 2>/dev/null

case "${1:-watch}" in
  update) if [ -n "${2:-}" ]; then update_to "$2"; else check_once; fi ;;
  watch)  ETAG=""; log "probe started, polling every ${INTERVAL}s"
          while true; do check_once; watchdog_check; sync_forward; sleep "$INTERVAL"; done ;;
  *)      echo "usage: gamebond-probe [watch|update [SHA]]" >&2; exit 2 ;;
esac
