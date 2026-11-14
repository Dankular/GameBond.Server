#!/bin/bash
# Installs a Gitea Actions runner on a dedicated build machine (Debian/Ubuntu, run as root).
#
#   GITEA_URL=https://gitea.app.khosa.co REG_TOKEN=<registration token> RUNNER_NAME=builder-1 \
#     bash install-gitea-runner.sh
#
# The runner executes jobs directly on this machine (host mode) with its Docker, so use it only
# on a box that exists for builds. It takes the `ubuntu-latest` label: remove that label from
# any other runner (for example the one on the app host) so builds land here.
# Registration token: Gitea API  GET /api/v1/admin/runners/registration-token
set -euo pipefail
: "${GITEA_URL:?set GITEA_URL}" "${REG_TOKEN:?set REG_TOKEN}"
NAME=${RUNNER_NAME:-builder-1}
VERSION=${ACT_RUNNER_VERSION:-0.2.13}
LABELS=${RUNNER_LABELS:-ubuntu-latest:host,self-hosted:host}

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
if ! command -v docker >/dev/null; then
  apt-get update -qq && apt-get install -y -qq ca-certificates curl git
  curl -fsSL https://get.docker.com | sh
fi
apt-get install -y -qq git curl >/dev/null

id gitea-runner >/dev/null 2>&1 || useradd -r -m -d /opt/act_runner -s /bin/bash -G docker gitea-runner
install -d -o gitea-runner -g gitea-runner /opt/act_runner
cd /opt/act_runner
curl -fsSL -o act_runner "https://dl.gitea.com/act_runner/$VERSION/act_runner-$VERSION-linux-amd64"
chmod +x act_runner
if [ ! -f .runner ]; then
  sudo -u gitea-runner ./act_runner register --no-interactive --instance "$GITEA_URL" \
    --token "$REG_TOKEN" --name "$NAME" --labels "$LABELS"
fi

cat > /etc/systemd/system/act-runner.service <<UNIT
[Unit]
Description=Gitea Actions runner ($NAME)
After=network-online.target docker.service
Wants=network-online.target
[Service]
User=gitea-runner
WorkingDirectory=/opt/act_runner
ExecStart=/opt/act_runner/act_runner daemon
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now act-runner
sleep 3
systemctl is-active act-runner
