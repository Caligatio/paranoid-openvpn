from enum import Enum, unique


@unique
class TLSVersion(Enum):
    v1_0 = "1.0"
    v1_1 = "1.1"
    v1_2 = "1.2"
    v1_3 = "1.3"
