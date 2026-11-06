import importlib.util
import sys
from pathlib import Path

import pytest

import usbtether
from usbtether import enroll

PATH = Path(__file__).resolve().parents[1] / "examples" / "sdk_quickstart.py"


def load():
    spec = importlib.util.spec_from_file_location("sdk_quickstart", PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_quickstart_runs_against_an_enrolled_drive(stick, probe, registry):
    _, mount = stick
    enroll(probe, registry, mount)
    assert load().run(probe, registry) == "write performed"


def test_quickstart_is_denied_without_enrollment(probe, registry):
    with pytest.raises(usbtether.UsbTetherError):
        load().run(probe, registry)


def test_public_api_is_importable():
    for name in usbtether.__all__:
        assert hasattr(usbtether, name), name
