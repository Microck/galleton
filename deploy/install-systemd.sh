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
unit_path="$unit_dir/galleton.service"
backup=
new_unit=
had_unit=false
was_enabled=false
was_active=false
cleanup() {
  [ -z "$new_unit" ] || rm -f "$new_unit"
  [ -z "$backup" ] || rm -f "$backup"
}
trap cleanup 0 HUP INT TERM
if [ -f "$unit_path" ]; then
  had_unit=true
  backup=$(mktemp "$unit_dir/.galleton.service.backup.XXXXXX")
  cp "$unit_path" "$backup"
fi
systemctl --user is-enabled --quiet galleton.service && was_enabled=true || :
systemctl --user is-active --quiet galleton.service && was_active=true || :
new_unit=$(mktemp "$unit_dir/.galleton.service.new.XXXXXX")
cat > "$new_unit" <<UNIT
[Unit]
Description=Galleton local session renewal
After=network-online.target

[Service]
Type=simple
ExecStart="$binary" serve --dir "$state" --config "$config"
Restart=on-failure
RestartSec=5
TimeoutStopSec=330
NoNewPrivileges=yes
UMask=0077

[Install]
WantedBy=default.target
UNIT
chmod 600 "$new_unit"
mv "$new_unit" "$unit_path"
new_unit=
if ! systemctl --user daemon-reload ||
   ! systemctl --user enable galleton.service ||
   ! systemctl --user restart galleton.service; then
  systemctl --user stop galleton.service || :
  if [ "$had_unit" = true ]; then
    cp "$backup" "$unit_path"
  else
    rm -f "$unit_path"
  fi
  systemctl --user daemon-reload || :
  if [ "$had_unit" = true ]; then
    if [ "$was_enabled" = true ]; then
      systemctl --user enable galleton.service || :
    else
      systemctl --user disable galleton.service || :
    fi
    if [ "$was_active" = true ]; then
      systemctl --user restart galleton.service || :
    else
      systemctl --user stop galleton.service || :
    fi
  fi
  exit 1
fi
