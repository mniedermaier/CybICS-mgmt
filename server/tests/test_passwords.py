"""The admin password set at the first visit, changing it, and the Raspberry Pi's pi password and settings."""
import importlib.machinery
import importlib.util
import json
import os

import pytest

from conftest import ADMIN_PASSWORD, SIGNING_KEY
from cybics_mgmt import create_app, host
from cybics_mgmt.db import get_db
from cybics_mgmt.security import limiter

CSRF = {"csrf": "csrf-test"}


@pytest.fixture
def fresh(tmp_path, monkeypatch):
    """A server without MGMT_ADMIN_PASSWORD: the first visit sets the admin password."""
    monkeypatch.delenv("MGMT_ADMIN_PASSWORD", raising=False)
    limiter.reset()
    host_dir = tmp_path / "host"
    host_dir.mkdir()
    app = create_app({"TESTING": True, "DATA_DIR": str(tmp_path), "DATABASE": str(tmp_path / "db.sqlite"),
                      "SECRET_KEY": "test", "FLEET_SIGNING_KEY": SIGNING_KEY, "HOST_DIR": str(host_dir)})
    yield app
    limiter.reset()


def browser(app):
    client = app.test_client()
    with client.session_transaction() as sess:
        sess["csrf"] = "csrf-test"
    return client


def set_up(client, password="first-admin-pw", confirm=None):
    resp = client.post("/admin/setup", data={**CSRF, "password": password, "confirm": confirm or password},
                       follow_redirects=True)
    # Logging in starts a fresh session with a new CSRF token, as a browser
    # would receive with the next page; the tests keep using the known one.
    with client.session_transaction() as sess:
        sess["csrf"] = "csrf-test"
    return resp


def test_the_first_visit_sets_the_admin_password(fresh):
    client = browser(fresh)
    assert client.get("/admin/").headers["Location"].endswith("/admin/login?next=/admin/")
    assert client.get("/admin/login").headers["Location"].endswith("/admin/setup")
    assert b"Set the admin password" in client.get("/admin/setup").data
    page = set_up(client)
    assert b"Admin password set" in page.data and client.get("/admin/").status_code == 200
    with fresh.app_context():
        stored = get_db().execute("SELECT password_hash FROM admin_credentials").fetchone()[0]
    assert "first-admin-pw" not in stored                        # a hash only
    # Afterwards the setup page is gone and the password logs in.
    other = browser(fresh)
    assert other.get("/admin/setup").headers["Location"].endswith("/admin/login")
    assert set_up(other, "takeover-pw-1").request.path == "/admin/login"
    resp = other.post("/admin/login", data={**CSRF, "password": "first-admin-pw"})
    assert resp.status_code == 302 and other.get("/admin/").status_code == 200
    assert b"admin_password_set" in other.get("/admin/").data   # on the organiser log list


@pytest.mark.parametrize("password, confirm, message", [
    ("short", "short", b"at least 8 characters"),
    ("first-admin-pw", "other-admin-pw", b"two passwords differ"),
    ("password", "password", b"too easy to guess"),
    ("aaaaaaaaaa", "aaaaaaaaaa", b"too easy to guess"),
    ("x" * 257, "x" * 257, b"at most 256"),
])
def test_weak_setup_passwords_are_refused(fresh, password, confirm, message):
    client = browser(fresh)
    page = set_up(client, password, confirm)
    assert message in page.data
    with fresh.app_context():
        assert get_db().execute("SELECT COUNT(*) FROM admin_credentials").fetchone()[0] == 0


def test_the_first_one_to_set_it_wins(fresh):
    from cybics_mgmt.security import set_admin_password
    with fresh.test_request_context():
        assert set_admin_password("first-admin-pw", first=True) is True
        assert set_admin_password("second-admin-pw", first=True) is False


def test_an_admin_password_from_the_environment_skips_the_setup(app, client):
    assert client.get("/admin/setup").headers["Location"].endswith("/admin/login")
    assert client.get("/admin/login").status_code == 200


def test_changing_the_admin_password_ends_other_sessions(fresh):
    first, second = browser(fresh), browser(fresh)
    set_up(first)
    second.post("/admin/login", data={**CSRF, "password": "first-admin-pw"})
    with second.session_transaction() as sess:
        sess["csrf"] = "csrf-test"
    assert second.get("/admin/").status_code == 200
    page = first.post("/admin/password", data={**CSRF, "target": "admin", "current": "wrong-pw-123",
                                               "password": "next-admin-pw", "confirm": "next-admin-pw"},
                      follow_redirects=True)
    assert b"current password is wrong" in page.data
    page = first.post("/admin/password", data={**CSRF, "target": "admin", "current": "first-admin-pw",
                                               "password": "next-admin-pw", "confirm": "next-admin-pw"},
                      follow_redirects=True)
    assert b"Every other session has ended" in page.data
    with first.session_transaction() as sess:
        sess["csrf"] = "csrf-test"
    assert first.get("/admin/").status_code == 200              # the one who changed it stays in
    assert second.get("/admin/").status_code == 302             # everyone else is out
    assert second.post("/admin/login", data={**CSRF, "password": "next-admin-pw"}).status_code == 302


def test_an_environment_password_cannot_be_changed_in_the_browser(admin, app):
    page = admin.get("/admin/password").data
    assert b"MGMT_ADMIN_PASSWORD" in page and b'name="current"' not in page
    admin.post("/admin/password", data={**CSRF, "target": "admin", "current": ADMIN_PASSWORD,
                                        "password": "next-admin-pw", "confirm": "next-admin-pw"})
    assert app.config["ADMIN_PASSWORD"] == ADMIN_PASSWORD


def test_reset_from_the_command_line(fresh):
    client = browser(fresh)
    set_up(client)
    result = fresh.test_cli_runner().invoke(args=["reset-admin-password"])
    assert result.exit_code == 0 and "next visit" in result.output
    assert client.get("/admin/").status_code == 302              # the session ended with it
    assert client.get("/admin/login").headers["Location"].endswith("/admin/setup")


def test_reset_refuses_an_environment_password(app):
    result = app.test_cli_runner().invoke(args=["reset-admin-password"])
    assert result.exit_code != 0 and "MGMT_ADMIN_PASSWORD" in result.output


# ---------- the Raspberry Pi's pi password ----------

def logged_in(fresh):
    client = browser(fresh)
    set_up(client)
    return client


def test_the_pi_password_goes_to_the_host_directory(fresh):
    client = logged_in(fresh)
    host_dir = fresh.config["HOST_DIR"]
    assert b"Raspberry Pi login" in client.get("/admin/password").data
    page = client.post("/admin/password", data={**CSRF, "target": "pi", "current": "first-admin-pw",
                                                "password": "new-pi-pass", "confirm": "new-pi-pass"},
                       follow_redirects=True)
    assert b"Sent to the Raspberry Pi" in page.data and b"being applied" in page.data
    request = os.path.join(host_dir, "pi-password.json")
    assert os.stat(request).st_mode & 0o777 == 0o600
    with open(request) as f:
        assert json.load(f) == {"user": "pi", "password": "new-pi-pass"}
    with fresh.app_context():
        log = [r[0] for r in get_db().execute("SELECT action FROM admin_log")]
    assert "pi_password_requested" in log


@pytest.mark.parametrize("password, confirm, message", [
    ("short", "short", b"8 to 128"),
    ("new-pi-pass", "other-pass", b"two passwords differ"),
    ("raspberry", "raspberry", b"too easy to guess"),
    ("bad\npassword", "bad\npassword", b"control characters"),
])
def test_bad_pi_passwords_are_refused(fresh, password, confirm, message):
    client = logged_in(fresh)
    page = client.post("/admin/password", data={**CSRF, "target": "pi", "current": "first-admin-pw",
                                                "password": password, "confirm": confirm}, follow_redirects=True)
    assert message in page.data
    assert not os.path.exists(os.path.join(fresh.config["HOST_DIR"], "pi-password.json"))


@pytest.mark.parametrize("current", ["", "wrong-admin-pw"])
def test_the_pi_password_needs_the_admin_password(fresh, current):
    """It also allows sudo on the Pi: a stolen admin session alone must not be enough."""
    client = logged_in(fresh)
    page = client.post("/admin/password", data={**CSRF, "target": "pi", "current": current,
                                                "password": "new-pi-pass", "confirm": "new-pi-pass"},
                       follow_redirects=True)
    assert b"current admin password is wrong" in page.data
    assert not os.path.exists(os.path.join(fresh.config["HOST_DIR"], "pi-password.json"))


def test_the_host_status_is_shown_and_warned_about(fresh):
    client = logged_in(fresh)
    with open(os.path.join(fresh.config["HOST_DIR"], "status.json"), "w") as f:
        json.dump({"pi_default_password": True, "last": {"state": "failed", "detail": "chpasswd: boom",
                                                        "time": 1.0}}, f)
    events = client.get("/admin/").data
    assert b"still has the default login" in events
    page = client.get("/admin/password").data
    assert b"chpasswd: boom" in page and b">failed<" in page
    with open(os.path.join(fresh.config["HOST_DIR"], "status.json"), "w") as f:
        f.write("not json")
    assert b"still has the default login" not in client.get("/admin/").data


def test_without_a_host_directory_there_is_no_pi_section(admin):
    page = admin.get("/admin/password").data
    assert b"Raspberry Pi login" not in page
    admin.post("/admin/password", data={**CSRF, "target": "pi", "password": "new-pi-pass",
                                        "confirm": "new-pi-pass"})


# ---------- the Raspberry Pi's settings (cybics-mgmt.txt) ----------

PI_SETTINGS = {"WIFI_SSID": "cybics-mgmt", "WIFI_PASSWORD": "cybics-mgmt", "WIFI_COUNTRY": "US", "WIFI_CHANNEL": "6",
               "DEFAULT_ENROL_CODE": "CYBICS-BOARDS", "SERVER_NAME": "CybICS-mgmt", "HDMI_SCOREBOARD": "auto",
               "HDMI_THEME": "dark"}


def reported(app, **extra):
    """What cybics-mgmt-host reports: the settings now in cybics-mgmt.txt."""
    with open(os.path.join(app.config["HOST_DIR"], "status.json"), "w") as f:
        json.dump({"pi_default_password": False, "settings": dict(PI_SETTINGS), **extra}, f)


def save(client, current="first-admin-pw", **changes):
    return client.post("/admin/pi", data={**CSRF, **PI_SETTINGS, "current": current, **changes},
                       follow_redirects=True)


def settings_request(app):
    path = os.path.join(app.config["HOST_DIR"], "settings.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def test_the_pi_settings_page_shows_what_the_pi_reports(fresh):
    client = logged_in(fresh)
    assert b"has not reported its settings yet" in client.get("/admin/pi").data
    reported(fresh, problems=["line 3: unknown setting 'FOO'"], settings_last={"state": "done", "detail": "changed X",
                                                                               "time": 1.0})
    page = client.get("/admin/pi").data
    assert b'value="cybics-mgmt"' in page and b"unknown setting" in page and b"changed X" in page
    assert b">Raspberry Pi</a>" in client.get("/admin/").data   # in the header on every admin page


def test_only_changed_settings_go_to_the_host(fresh):
    client = logged_in(fresh)
    reported(fresh)
    page = save(client, HDMI_SCOREBOARD="ON", HDMI_THEME="light", DEFAULT_ENROL_CODE="room-2")
    assert b"Sent to the Raspberry Pi" in page.data and b"server restarts" in page.data
    assert settings_request(fresh) == {"settings": {"HDMI_SCOREBOARD": "on", "HDMI_THEME": "light",
                                                    "DEFAULT_ENROL_CODE": "ROOM-2"}}
    assert os.stat(os.path.join(fresh.config["HOST_DIR"], "settings.json")).st_mode & 0o777 == 0o600
    assert b"being applied" in client.get("/admin/pi").data
    with fresh.app_context():
        details = [r[0] for r in get_db().execute(
            "SELECT details FROM admin_log WHERE action = 'pi_settings_requested'")]
    assert len(details) == 1 and "HDMI_THEME" in details[0]


def test_wifi_changes_need_a_confirmation_and_stay_out_of_the_log(fresh):
    client = logged_in(fresh)
    reported(fresh)
    page = save(client, WIFI_PASSWORD="new-wifi-secret")
    assert b"Tick the box" in page.data and settings_request(fresh) is None
    page = save(client, WIFI_PASSWORD="new-wifi-secret", confirm_wifi="1")
    assert b"access point restarts" in page.data
    assert settings_request(fresh) == {"settings": {"WIFI_PASSWORD": "new-wifi-secret"}}
    with fresh.app_context():
        assert not get_db().execute("SELECT 1 FROM admin_log WHERE details LIKE '%new-wifi-secret%'").fetchone()


def test_a_new_channel_restarts_the_access_point(fresh):
    client = logged_in(fresh)
    reported(fresh)
    assert b'<option value="6" selected>' in client.get("/admin/pi").data
    assert b"Tick the box" in save(client, WIFI_CHANNEL="11").data
    save(client, WIFI_CHANNEL="11", confirm_wifi="1")
    assert settings_request(fresh) == {"settings": {"WIFI_CHANNEL": "11"}}


@pytest.mark.parametrize("changes, message", [
    ({"WIFI_SSID": "bad\\name"}, b"Wi-Fi name must be"),
    ({"WIFI_PASSWORD": "short"}, b"Wi-Fi password must be"),
    ({"WIFI_COUNTRY": "Germany"}, b"Wi-Fi country must be"),
    ({"WIFI_CHANNEL": "14"}, b"Wi-Fi channel must be"),
    ({"WIFI_CHANNEL": "0"}, b"Wi-Fi channel must be"),
    ({"DEFAULT_ENROL_CODE": "a b"}, b"Enrolment code for boards must be"),
    ({"SERVER_NAME": "It's mine"}, b"Server name must be"),
    ({"SERVER_NAME": "two\nlines"}, b"Server name must be"),
    ({"HDMI_SCOREBOARD": "maybe"}, b"Scoreboard on HDMI must be"),
])
def test_invalid_pi_settings_are_refused(fresh, changes, message):
    client = logged_in(fresh)
    reported(fresh)
    assert message in save(client, confirm_wifi="1", **changes).data
    assert settings_request(fresh) is None


def test_pi_settings_need_the_admin_password_and_a_change(fresh):
    client = logged_in(fresh)
    reported(fresh)
    assert b"current admin password is wrong" in save(client, current="nope", HDMI_THEME="light").data
    assert b"Nothing changed" in save(client).data
    assert settings_request(fresh) is None


def test_without_a_host_directory_there_is_no_pi_page(admin):
    assert admin.get("/admin/pi").status_code == 404
    assert b">Raspberry Pi</a>" not in admin.get("/admin/").data


def test_the_settings_rules_match_the_ones_the_pi_applies_at_boot():
    """host.SETTINGS repeats cybics-mgmt-config's CHECKS for the UI; the host enforces the latter."""
    path = os.path.join(os.path.dirname(__file__), "..", "..", "image", "stage-mgmt", "02-app", "files",
                        "cybics-mgmt-config")
    loader = importlib.machinery.SourceFileLoader("cybics_mgmt_config", path)
    config = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(config)
    assert set(host.SETTINGS) == set(config.CHECKS) == set(config.DEFAULTS)
    samples = ["", "x", "ab", "DE", "de", "Germany", "cybics-mgmt", "pass\\word12", "a" * 33, "a" * 64, "a" * 65,
               "CYBICS-BOARDS", "room 2", "It's", "two\nlines", "auto", "ON", "off", "maybe", "dark", "Light",
               "Ünïcödé-Netz", "12345678", "0", "1", "06", "11", "13", "14", "100"]
    for key in host.SETTINGS:
        for value in samples:
            clean, problems = host.settings_problems({key: value})
            normalised = config.normalise(key, value)
            assert (not problems) == bool(config.CHECKS[key][0](normalised)), (key, value)
            if not problems:
                assert clean[key] == normalised, (key, value)
        assert not host.settings_problems({key: config.DEFAULTS[key]})[1], key
