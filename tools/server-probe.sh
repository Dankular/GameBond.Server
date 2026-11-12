#!/bin/bash
# gamebond-probe: runs on the VPS. Watches GitHub Actions for a newer successful "server-image"
# build of main and, when there is one, performs a clean update: pull the image, recreate the
# container, wait until it is really ready, and put the previous image back if it is not.
#
#   gamebond-probe            watch forever (the systemd service)
#   gamebond-probe update     check once and update if a newer build exists
#   gamebond-probe update SHA update to that commit's image (must already be built)
set -u
REPO=Dankular/GameBond.Server
WORKFLOW=server-image.yml
IMAGE_REPO=ghcr.io/dankular/gamebond-server
RELEASE=/opt/gamebond/releases/native-live
ENVFILE=$RELEASE/deploy.env
CONTAINER=gamebond-native-1
STATE=/var/lib/gamebond-probe
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

update_to() {
  local sha=$1 want="$IMAGE_REPO:$1" prev
  prev=$(current_image)
  [ "$prev" = "$want" ] && return 0
  exec 9>/var/lock/gamebond-update; flock -w 120 9 || { log "another update holds the lock"; return 1; }
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

case "${1:-watch}" in
  update) if [ -n "${2:-}" ]; then update_to "$2"; else check_once; fi ;;
  watch)  ETAG=""; log "probe started, polling every ${INTERVAL}s"
          while true; do check_once; sleep "$INTERVAL"; done ;;
  *)      echo "usage: gamebond-probe [watch|update [SHA]]" >&2; exit 2 ;;
esac
