#!/bin/sh
# Optional, user-invoked installer. Never called by session import.
set -eu
if [ "$#" -ne 3 ]; then
  echo "Usage: $0 /absolute/galleton /absolute/state /absolute/adapters.json" >&2
  exit 2
fi
binary=$1; state=$2; config=$3
for path in "$binary" "$state" "$config"; do
  case "$path" in /*) ;; *) echo "Absolute paths are required" >&2; exit 2;; esac
  case "$path" in *'%'*|*'$'*|*'"'*|*'\'*|*'
'*) echo "Paths containing percent, dollar signs, quotes, backslashes or newlines are unsupported" >&2; exit 2;; esac
done
[ -x "$binary" ] && [ -f "$state/api.token" ] && [ -f "$config" ] || { echo "Build and initialize Galleton first" >&2; exit 2; }
unit_dir=${XDG_CONFIG_HOME:-"$HOME/.config"}/systemd/user
mkdir -p "$unit_dir"
umask 077
cat > "$unit_dir/galleton.service" <<UNIT
[Unit]
Description=Galleton local session renewal
After=network-online.target

[Service]
Type=simple
ExecStart="$binary" serve --dir "$state" --config "$config"
Restart=on-failure
RestartSec=5
TimeoutStopSec=300
NoNewPrivileges=yes
UMask=0077

[Install]
WantedBy=default.target
UNIT
systemctl --user daemon-reload
systemctl --user enable galleton.service
systemctl --user restart galleton.service
