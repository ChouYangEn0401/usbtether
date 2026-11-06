"""usbtether: bind sessions to an ordinary USB drive.

Typical use::

    from usbtether import Agent, Authorizer, Registry, Verifier, default_probe

    probe = default_probe()
    verifier = Verifier(Registry.default())
    authorizer = Authorizer(verifier)
    agent = Agent(probe)

    session = authorizer.open_session_local(agent)
    capability = authorizer.issue_capability_local(agent, session.session_id, "db", "write")
    authorizer.consume(capability, resource="db", action="write")

See the README and ``docs/`` for the protocol and the (limited) security guarantees.
"""

__version__ = "0.1.0"

from .agent import Agent, TokenCandidate
from .authz import Authorizer, Capability, Session, capability_purpose
from .device import DeviceReport, SerialQuality, UsbDevice, Volume
from .enrollment import EnrollmentResult, enroll
from .errors import (
    AlreadyEnrolledError,
    AmbiguousDeviceError,
    AuthorizationError,
    DeviceNotFoundError,
    ProbeError,
    ProtocolError,
    RegistryError,
    TokenError,
    TokenLockedError,
    UnsupportedDeviceError,
    UnsupportedPlatformError,
    UsbTetherError,
)
from .monitor import PresenceMonitor
from .probe import DeviceProbe, InMemoryProbe, default_probe
from .protocol import AuthResult, Challenge, FailureReason, Response
from .registry import Registry, RegistryEntry
from .verifier import Verifier

__all__ = [
    "Agent",
    "AlreadyEnrolledError",
    "AmbiguousDeviceError",
    "AuthResult",
    "AuthorizationError",
    "Authorizer",
    "Capability",
    "Challenge",
    "DeviceNotFoundError",
    "DeviceProbe",
    "DeviceReport",
    "EnrollmentResult",
    "FailureReason",
    "InMemoryProbe",
    "PresenceMonitor",
    "ProbeError",
    "ProtocolError",
    "Registry",
    "RegistryEntry",
    "RegistryError",
    "Response",
    "SerialQuality",
    "Session",
    "TokenCandidate",
    "TokenError",
    "TokenLockedError",
    "UnsupportedDeviceError",
    "UnsupportedPlatformError",
    "UsbDevice",
    "UsbTetherError",
    "Verifier",
    "Volume",
    "__version__",
    "capability_purpose",
    "default_probe",
    "enroll",
]
