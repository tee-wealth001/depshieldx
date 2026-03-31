import json
import os
from pathlib import Path

from .cache import get_cache_root


ROUTING_STATE_VERSION = 2


def _is_windows() -> bool:
    return os.name == "nt"


def _routing_root() -> Path:
    return get_cache_root() / "routing"


def _state_path() -> Path:
    return _routing_root() / "state.json"


def _shim_dir() -> Path:
    return _routing_root() / "shims"


def _shim_filename() -> str:
    return "pip.bat" if _is_windows() else "pip"


def _shim_path() -> Path:
    return _shim_dir() / _shim_filename()


def _known_shim_paths() -> tuple[Path, ...]:
    shim_dir = _shim_dir()
    return (
        shim_dir / "pip",
        shim_dir / "pip.bat",
    )


def _activation_hint(shim_dir: Path) -> str:
    if _is_windows():
        return (
            f'PowerShell: $env:PATH = "{shim_dir};$env:PATH"'
            f" | cmd.exe: set PATH={shim_dir};%PATH%"
        )
    return f'export PATH="{shim_dir}:$PATH"'


def _shim_contents() -> str:
    if _is_windows():
        return "@echo off\r\ndepshieldx route-pip %*\r\n"
    return "#!/bin/sh\nexec depshieldx route-pip \"$@\"\n"


def _write_state(enabled: bool, prompt_dismissed: bool) -> None:
    _routing_root().mkdir(parents=True, exist_ok=True)
    _state_path().write_text(
        json.dumps(
            {
                "state_version": ROUTING_STATE_VERSION,
                "enabled": enabled,
                "prompt_dismissed": prompt_dismissed,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def get_routing_status() -> dict:
    enabled = False
    prompt_dismissed = False
    try:
        payload = json.loads(_state_path().read_text())
        if payload.get("state_version") == ROUTING_STATE_VERSION:
            enabled = bool(payload.get("enabled") and any(path.exists() for path in _known_shim_paths()))
            prompt_dismissed = bool(payload.get("prompt_dismissed"))
    except Exception:
        enabled = False
        prompt_dismissed = False

    shim_dir = _shim_dir()
    return {
        "enabled": enabled,
        "prompt_dismissed": prompt_dismissed,
        "shim_dir": str(shim_dir),
        "shim_path": str(_shim_path()),
        "activation_hint": _activation_hint(shim_dir),
    }


def enable_routing() -> dict:
    root = _routing_root()
    root.mkdir(parents=True, exist_ok=True)
    shim_dir = _shim_dir()
    shim_dir.mkdir(parents=True, exist_ok=True)

    for path in _known_shim_paths():
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    shim = _shim_path()
    shim.write_text(_shim_contents())
    if not _is_windows():
        shim.chmod(0o755)
    _write_state(enabled=True, prompt_dismissed=False)
    return get_routing_status()


def disable_routing() -> dict:
    for path in _known_shim_paths():
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    try:
        _write_state(enabled=False, prompt_dismissed=True)
    except Exception:
        pass
    return get_routing_status()


def dismiss_routing_prompt() -> dict:
    try:
        _write_state(enabled=False, prompt_dismissed=True)
    except Exception:
        pass
    return get_routing_status()


def should_prompt_for_routing() -> bool:
    if os.environ.get("DEPSHIELDX_NO_ROUTING_PROMPT") == "1":
        return False
    status = get_routing_status()
    return not status["enabled"] and not status["prompt_dismissed"]
