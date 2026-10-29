"""
Requests to the machine the server runs on, for the CybICS-mgmt Raspberry Pi
image only: setting the password of its "pi" account, and the settings of
cybics-mgmt.txt (Wi-Fi, enrolment code, server name, HDMI), from the admin UI.

The server runs as a non-root user in a read-only container and cannot change
anything on the host itself. With MGMT_HOST_DIR set (the image mounts the
host's /run/cybics-mgmt there, a tmpfs, so a password never reaches the SD
card), it writes a request file; a root service on the host
(cybics-mgmt-host, started by a systemd path unit) applies it with chpasswd,
deletes it and answers in status.json. Without MGMT_HOST_DIR none of this
exists.

The settings are checked here for a readable error, and again on the host,
which only knows the keys of cybics-mgmt.txt (cybics-mgmt-config holds the
rules both follow). The host writes them into cybics-mgmt.txt, so the file on
the SD card and this page never disagree, and reports the current values in
status.json.
"""
import json
import os
import re

from flask import current_app

REQUEST = "pi-password.json"
SETTINGS_REQUEST = "settings.json"
STATUS = "status.json"
PI_PASSWORD_MIN = 8
PI_PASSWORD_MAX = 128

# The keys of cybics-mgmt.txt, with the rules cybics-mgmt-config applies at
# boot (image/stage-mgmt/02-app/files/cybics-mgmt-config); keep both in sync.
# (label, check, rule, normalise)
SETTINGS = {
    "WIFI_SSID": ("Wi-Fi name", lambda v: 1 <= len(v.encode()) <= 32 and v.isprintable() and "\\" not in v,
                  "1 to 32 characters without a backslash", str),
    "WIFI_PASSWORD": ("Wi-Fi password", lambda v: re.fullmatch(r"[\x20-\x5b\x5d-\x7e]{8,63}", v),
                      "8 to 63 printable ASCII characters without a backslash", str),
    "WIFI_COUNTRY": ("Wi-Fi country", lambda v: re.fullmatch(r"[A-Z]{2}", v), "a two-letter country code",
                     str.upper),
    "WIFI_CHANNEL": ("Wi-Fi channel", lambda v: re.fullmatch(r"[1-9]|1[0-3]", v), "a 2.4 GHz channel from 1 to 13",
                     str),
    "DEFAULT_ENROL_CODE": ("Enrolment code for boards",
                           lambda v: v == "" or re.fullmatch(r"[A-Z0-9][A-Z0-9-]{3,15}", v),
                           "empty, or 4 to 16 letters, digits or dashes", str.upper),
    "SERVER_NAME": ("Server name", lambda v: 1 <= len(v) <= 64 and "'" not in v and v.isprintable(),
                    "1 to 64 characters without a ' quote", str),
    "HDMI_SCOREBOARD": ("Scoreboard on HDMI", lambda v: v in ("auto", "on", "off"), "auto, on or off", str.lower),
    "HDMI_THEME": ("HDMI theme", lambda v: v in ("dark", "light"), "dark or light", str.lower),
}
WIFI_KEYS = ("WIFI_SSID", "WIFI_PASSWORD", "WIFI_COUNTRY", "WIFI_CHANNEL")


def directory():
    path = current_app.config.get("HOST_DIR") or ""
    return path if path and os.path.isdir(path) else None


def _last(value):
    if isinstance(value, dict) and value.get("state") in ("done", "failed"):
        return {"state": value["state"], "detail": str(value.get("detail") or "")[:200],
                "time": value.get("time") if isinstance(value.get("time"), (int, float)) else None}
    return None


def status():
    """
    What the host last reported: {"pi_default_password": bool|None, "last": {...}|None,
    "pending": bool, "settings": {key: str}|None, "settings_last": {...}|None,
    "settings_pending": bool, "problems": [str]}.
    """
    path = directory()
    result = {"pi_default_password": None, "last": None, "pending": False, "settings": None,
              "settings_last": None, "settings_pending": False, "problems": []}
    if path is None:
        return result
    try:
        with open(os.path.join(path, STATUS), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError, RecursionError):
        data = {}
    if isinstance(data, dict):
        if isinstance(data.get("pi_default_password"), bool):
            result["pi_default_password"] = data["pi_default_password"]
        result["last"] = _last(data.get("last"))
        result["settings_last"] = _last(data.get("settings_last"))
        settings = data.get("settings")
        if isinstance(settings, dict):
            result["settings"] = {k: settings[k] for k in SETTINGS if isinstance(settings.get(k), str)}
        problems = data.get("problems")
        if isinstance(problems, list):
            result["problems"] = [str(p)[:200] for p in problems[:20]]
    result["pending"] = os.path.exists(os.path.join(path, REQUEST))
    result["settings_pending"] = os.path.exists(os.path.join(path, SETTINGS_REQUEST))
    return result


def pi_password_problem(password, confirm):
    """Why `password` cannot become the pi account's password, or None."""
    if password != confirm:
        return "The two passwords differ."
    if not PI_PASSWORD_MIN <= len(password) <= PI_PASSWORD_MAX:
        return f"The password needs {PI_PASSWORD_MIN} to {PI_PASSWORD_MAX} characters."
    if re.search(r"[\x00-\x1f\x7f]", password):
        return "The password may not contain control characters."
    if password == "raspberry" or len(set(password)) == 1:  # noqa: S105 (the image's published default)
        return "This password is too easy to guess."
    return None


def settings_problems(values):
    """
    The settings normalised as cybics-mgmt-config reads them, and a list of
    what is wrong with them. Unknown keys are refused; missing ones stay as
    they are.
    """
    clean, problems = {}, []
    for key, value in values.items():
        if key not in SETTINGS:
            problems.append(f"Unknown setting {key}.")
            continue
        label, check, rule, normalise = SETTINGS[key]
        value = normalise(str(value).strip())
        if check(value):
            clean[key] = value
        else:
            problems.append(f"{label} must be {rule}.")
    return clean, problems


def _request(name, data):
    """Hand a request to the host. The file is private and appears atomically."""
    path = directory()
    if path is None:
        raise RuntimeError("No host directory: this server does not run on the CybICS-mgmt Raspberry Pi image.")
    tmp = os.path.join(path, f".{name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f)
    os.replace(tmp, os.path.join(path, name))


def request_pi_password(password):
    _request(REQUEST, {"user": "pi", "password": password})


def request_settings(settings):
    """Settings for cybics-mgmt.txt, already checked with settings_problems()."""
    _request(SETTINGS_REQUEST, {"settings": settings})
