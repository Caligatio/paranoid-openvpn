from enum import Enum, auto, unique


@unique
class TLSVersion(Enum):
    """Enum for desired minimum TLS version to require."""

    v1_0 = "1.0"
    v1_1 = "1.1"
    v1_2 = "1.2"
    v1_3 = "1.3"


@unique
class CipherStrength(Enum):
    """Enum to denote the relative cipher strength level of a OVPN profile."""

    WEAK = auto()
    ACCEPTABLE = auto()
    MEDIUM = auto()
    STRONG = auto()


@unique
class ProviderExtensions(Enum):
    """Enum for which, if any, provider-specific customization to perform."""

    NONE = auto()
    PIA = auto()
