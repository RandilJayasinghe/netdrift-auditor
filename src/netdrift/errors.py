class NetDriftError(Exception):
    """Base class for all expected, user-reportable errors."""


class ParseError(NetDriftError):
    """A configuration could not be parsed."""


class UnresolvedReference(NetDriftError):
    """An address/service object or group referenced by a rule does not exist."""


class ProfileError(NetDriftError):
    """The audit profile (entry points / critical assets) is invalid for this config."""


class SecretLeakError(NetDriftError):
    """Unsanitized secret material was about to be persisted or emitted."""
