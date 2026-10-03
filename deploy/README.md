# Optional startup installers

These files are operator-invoked installers, not actions performed automatically on credential import. They create a user-owned login/startup job running the daemon. No passwords are collected, and no administrator elevation is requested by the scripts themselves.

Initialize the state directory, validate the adapter, and stop any manually started daemon before installing a startup job. The same state directory cannot be opened by two daemon processes. Initial scripts use the default loopback port; edit the generated job to select a different `--listen` port for an additional instance.

Linux: `install-systemd.sh` enables `galleton.service` under the current user's systemd manager. User services normally depend on that manager being alive. It does not enable system-wide boot, user lingering, or privileged services.

macOS: `install-launchd.py` creates `~/Library/LaunchAgents/local.galleton.plist`, bootstraps it into the current GUI-user domain, and starts it. It needs Python 3 only for installation. No login session means no GUI-user LaunchAgent.

Windows: `install-windows.ps1` registers the `Galleton` task for the current interactive user at login. Reinstalling snapshots the prior task, disables recovery triggers, asks the running daemon to drain through its authenticated local shutdown endpoint, waits up to 330 seconds for persistence and exit, then replaces and starts the task. If replacement fails, it restores the prior definition, enabled state, and running state. A legacy daemon without that endpoint must be stopped manually before rerunning the installer. It does not configure a Windows service account or execute while that user is logged out. The state directory must have user-restricted Windows ACLs.

Environment-supplied OAuth client secrets and `GALLETON_MASTER_KEY` must be available in the actual service environment. Merely exporting them in the shell that ran the installer does not configure them for later logins. The supplied installers intentionally do not copy shell credentials into service files.

Uninstall:

```sh
# Linux
systemctl --user disable --now galleton.service
rm ~/.config/systemd/user/galleton.service
systemctl --user daemon-reload

# macOS (run from the owning user account)
launchctl bootout gui/$(id -u)/local.galleton
rm ~/Library/LaunchAgents/local.galleton.plist
```

```powershell
# Windows
Stop-ScheduledTask -TaskName Galleton
Unregister-ScheduledTask -TaskName Galleton -Confirm:$false
```

Uninstalling a startup job does not delete encrypted state or revoke provider credentials. These installers were supplied but not executed during local verification.
