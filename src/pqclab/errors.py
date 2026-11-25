"""Public operational error categories."""


class LabError(Exception):
    """Base class for expected lab failures."""


class CryptoFailure(LabError):
    """Authentication or cryptographic operation failed."""


class FormatError(LabError):
    """Invalid or unsupported input format."""


class BackendUnavailable(LabError):
    """Required cryptographic backend is unavailable."""


class OutputExists(LabError):
    """Refuse to overwrite an existing destination."""


class Cancelled(LabError):
    """Operation cancelled before publication."""
