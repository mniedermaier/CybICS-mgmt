"""The Raspberry Pi image's access point: its channel, and it comes up only once the server answers."""
import importlib.machinery
import importlib.util
import os
import re

import pytest

STAGE = os.path.join(os.path.dirname(__file__), "..", "..", "image", "stage-mgmt")


def load(name):
    path = os.path.join(STAGE, "02-app", "files", name)
    loader = importlib.machinery.SourceFileLoader(name.replace("-", "_"), path)
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


@pytest.fixture
def profile(tmp_path):
    def write(text):
        path = tmp_path / "cybics-mgmt-ap.nmconnection"
        path.write_text(text, encoding="utf-8")
        return str(path)
    return write


def autoconnect(path):
    with open(path, encoding="utf-8") as f:
        return re.findall(r"(?m)^autoconnect=(.*)$", f.read())


def test_the_shipped_profile_does_not_start_the_access_point_by_itself():
    path = os.path.join(STAGE, "01-network", "files", "cybics-mgmt-ap.nmconnection")
    assert autoconnect(path) == ["false"]


def test_the_shipped_profile_stays_as_it_is(profile):
    with open(os.path.join(STAGE, "01-network", "files", "cybics-mgmt-ap.nmconnection"), encoding="utf-8") as f:
        shipped = f.read()
    path = profile(shipped)
    assert not load("cybics-mgmt-config").hold_back_autoconnect(path)
    with open(path, encoding="utf-8") as f:
        assert f.read() == shipped


def test_switched_on_during_the_last_boot_it_is_held_back_again(profile):
    path = profile("[connection]\nid=cybics-mgmt-ap\nautoconnect=true\nautoconnect-priority=100\n")
    assert load("cybics-mgmt-config").hold_back_autoconnect(path)
    assert autoconnect(path) == ["false"]
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"


def test_a_profile_networkmanager_rewrote_without_the_key_gets_it_back(profile):
    # nmcli drops autoconnect from the keyfile once it holds the default (true).
    path = profile("[connection]\nid=cybics-mgmt-ap\ntype=wifi\nautoconnect-priority=100\n\n[wifi]\nmode=ap\n")
    assert load("cybics-mgmt-config").hold_back_autoconnect(path)
    with open(path, encoding="utf-8") as f:
        text = f.read()
    assert text.startswith("[connection]\nautoconnect=false\nid=cybics-mgmt-ap\n")
    assert autoconnect(path) == ["false"]


def test_the_channel_from_cybics_mgmt_txt_goes_into_the_shipped_profile(profile):
    config = load("cybics-mgmt-config")
    with open(os.path.join(STAGE, "01-network", "files", "cybics-mgmt-ap.nmconnection"), encoding="utf-8") as f:
        path = profile(f.read())
    assert config.replace_lines(path, {"channel": "11"})
    with open(path, encoding="utf-8") as f:
        assert re.findall(r"(?m)^channel=(.*)$", f.read()) == ["11"]


@pytest.mark.parametrize("country, wanted, used", [
    ("DE", "13", "13"), ("US", "11", "11"), ("US", "13", "6"), ("CA", "12", "6"), ("GB", "1", "1"),
])
def test_a_channel_the_country_forbids_falls_back_to_the_default(country, wanted, used):
    config = load("cybics-mgmt-config")
    problems = []
    assert config.channel({"WIFI_COUNTRY": country, "WIFI_CHANNEL": wanted}, problems) == used
    assert bool(problems) == (wanted != used)


def test_the_shipped_settings_file_names_every_setting():
    config = load("cybics-mgmt-config")
    problems = []
    settings = config.read_settings(os.path.join(STAGE, "02-app", "files", "cybics-mgmt.txt"), problems)
    assert problems == [] and settings == config.DEFAULTS


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def test_the_access_point_waits_for_the_server():
    ap_up = load("cybics-mgmt-ap-up")
    clock = Clock()
    answers = iter([False, False, True])
    assert ap_up.wait_for_server(wait=300, ready=lambda: next(answers), clock=clock, sleep=clock.sleep)
    assert clock.now == 4


def test_without_a_server_the_access_point_comes_up_anyway():
    ap_up = load("cybics-mgmt-ap-up")
    clock = Clock()
    assert not ap_up.wait_for_server(wait=300, ready=lambda: False, clock=clock, sleep=clock.sleep)
    assert 300 <= clock.now < 303


def test_the_access_point_comes_up_and_reconnects_after_the_wait(monkeypatch):
    ap_up = load("cybics-mgmt-ap-up")
    calls = []

    class Done:
        returncode, stderr = 0, ""

    monkeypatch.setattr(ap_up, "wait_for_server", lambda: False)
    monkeypatch.setattr(ap_up.subprocess, "run", lambda args, **kw: calls.append(args) or Done())
    assert ap_up.main() == 0
    assert calls == [["nmcli", "connection", "modify", "cybics-mgmt-ap", "connection.autoconnect", "yes"],
                     ["nmcli", "connection", "up", "cybics-mgmt-ap"]]
