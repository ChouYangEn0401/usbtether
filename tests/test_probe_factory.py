import pytest

from usbtether.errors import UnsupportedPlatformError
from usbtether.probe import default_probe
from usbtether.probe.linux import LinuxProbe
from usbtether.probe.windows import WindowsProbe


def test_dispatch_by_platform(monkeypatch):
    monkeypatch.setattr("sys.platform", "win32")
    assert isinstance(default_probe(), WindowsProbe)
    monkeypatch.setattr("sys.platform", "linux")
    assert isinstance(default_probe(), LinuxProbe)


def test_unsupported_platform_has_a_clear_error(monkeypatch):
    monkeypatch.setattr("sys.platform", "darwin")
    with pytest.raises(UnsupportedPlatformError, match="darwin"):
        default_probe()
