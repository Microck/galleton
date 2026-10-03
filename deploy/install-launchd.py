#!/usr/bin/env python3
"""Install a per-user macOS LaunchAgent when explicitly invoked by the user."""
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile


def main():
    if sys.platform != "darwin" or len(sys.argv) != 4:
        raise SystemExit("On macOS: python3 install-launchd.py /binary /state /adapters.json")
    binary, state, config = [Path(p).expanduser().resolve() for p in sys.argv[1:]]
    if not binary.is_file() or not (state / "api.token").is_file() or not config.is_file():
        raise SystemExit("Build and initialize Galleton first")
    label = "local.galleton"
    destination = Path.home() / "Library/LaunchAgents" / (label + ".plist")
    destination.parent.mkdir(parents=True, exist_ok=True)
    content = {
        "Label": label,
        "ProgramArguments": [str(binary), "serve", "--dir", str(state), "--config", str(config)],
        "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 10,
        "ProcessType": "Background", "ExitTimeOut": 330,
        "StandardOutPath": str(state / "service.stdout.log"),
        "StandardErrorPath": str(state / "service.stderr.log"),
    }
    previous = destination.read_bytes() if destination.exists() else None
    domain = f"gui/{os.getuid()}"
    target = domain + "/" + label
    was_loaded = subprocess.run(
        ["launchctl", "print", target], check=False,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ).returncode == 0

    def write_plist(payload):
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as file:
            temporary = Path(file.name)
            file.write(payload)
        temporary.chmod(0o600)
        temporary.replace(destination)

    try:
        write_plist(plistlib.dumps(content))
        subprocess.run(["launchctl", "bootout", target], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["launchctl", "bootstrap", domain, str(destination)], check=True)
        subprocess.run(["launchctl", "kickstart", target], check=True)
    except Exception:
        subprocess.run(["launchctl", "bootout", target], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if previous is None:
            destination.unlink(missing_ok=True)
        else:
            write_plist(previous)
            if was_loaded:
                subprocess.run(["launchctl", "bootstrap", domain, str(destination)], check=True)
                subprocess.run(["launchctl", "kickstart", target], check=True)
        raise


if __name__ == "__main__":
    main()
