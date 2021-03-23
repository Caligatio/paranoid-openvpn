from enum import Enum, auto, unique


@unique
class TLSVersion(Enum):
    v1_0 = "1.0"
    v1_1 = "1.1"
    v1_2 = "1.2"
    v1_3 = "1.3"


@unique
class CipherStrength(Enum):
    WEAK = auto()
    ACCEPTABLE = auto()
    MEDIUM = auto()
    STRONG = auto()
