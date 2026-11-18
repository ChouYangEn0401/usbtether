"""usbtether: bind sessions to an ordinary USB drive.

Register a drive as a key and encrypt with it (see :mod:`usbtether.core`)::

    from usbtether import KeyRing

    ring = KeyRing()
    key = ring.register("E:", label="desk key", remember=True)
    blob = ring.encrypt(b"hello", key.key_id)
    assert ring.decrypt(blob) == b"hello"  # needs the drive plugged in

Sessions and capabilities::

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

__version__ = "0.3.0"

from .agent import Agent, TokenCandidate
from .authz import Authorizer, Capability, Session, capability_purpose
from .core import Drive, KeyRecord, KeyRing
from .device import DeviceReport, SerialQuality, UsbDevice, Volume
from .enrollment import EnrollmentResult, enroll
from .errors import (
    AlreadyEnrolledError,
    AmbiguousDeviceError,
    AuthorizationError,
    DeviceNotFoundError,
    DriveVerificationError,
    KeyNotPresentError,
    KeyRevokedError,
    NotEncryptedError,
    PasswordRequiredError,
    ProbeError,
    ProtocolError,
    RegistryError,
    SecretStoreError,
    TamperedError,
    TokenError,
    TokenLockedError,
    UnknownKeyError,
    UnsupportedDeviceError,
    UnsupportedPlatformError,
    UsbTetherError,
    VaultError,
    WrongKeyError,
    WrongPasswordError,
)
from .monitor import PresenceMonitor
from .probe import DeviceProbe, InMemoryProbe, default_probe
from .protocol import AuthResult, Challenge, FailureReason, Response
from .registry import Registry, RegistryEntry
from .secretstore import (
    DpapiSecretStore,
    FileSecretStore,
    HostSecretStore,
    NullSecretStore,
    default_secret_store,
)
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
    "DpapiSecretStore",
    "Drive",
    "DriveVerificationError",
    "EnrollmentResult",
    "FailureReason",
    "FileSecretStore",
    "HostSecretStore",
    "InMemoryProbe",
    "KeyNotPresentError",
    "KeyRecord",
    "KeyRevokedError",
    "KeyRing",
    "NotEncryptedError",
    "NullSecretStore",
    "PasswordRequiredError",
    "PresenceMonitor",
    "ProbeError",
    "ProtocolError",
    "Registry",
    "RegistryEntry",
    "RegistryError",
    "Response",
    "SecretStoreError",
    "SerialQuality",
    "Session",
    "TamperedError",
    "TokenCandidate",
    "TokenError",
    "TokenLockedError",
    "UnknownKeyError",
    "UnsupportedDeviceError",
    "UnsupportedPlatformError",
    "UsbDevice",
    "UsbTetherError",
    "VaultError",
    "Verifier",
    "Volume",
    "WrongKeyError",
    "WrongPasswordError",
    "__version__",
    "capability_purpose",
    "default_probe",
    "default_secret_store",
    "enroll",
]
