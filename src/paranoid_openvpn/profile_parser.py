import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, Sequence, TextIO, Union

from .types import CipherStrength

if sys.version_info >= (3, 8):
    from typing import Final
else:
    from typing_extensions import Final


INLINE_TAGS: Final = set(
    [
        "<crl-verify>",
        "<cert>",
        "<ca>",
        "<key>",
        "<tls-auth>",
        "<dh>",
        "<extra-certs>",
        "<pkcs12>",
        "<secret>",
        "<tls-crypt>",
        "<htt-proxy-user-pass>",
    ]
)


class OVPNConfigParam(ABC):
    @abstractmethod
    def write(self, f_out: TextIO) -> int:
        pass

    @classmethod
    @abstractmethod
    def read(cls, config: Sequence[str]) -> "OVPNConfigParam":
        pass

    @abstractmethod
    def __len__(self) -> int:
        pass

    @property
    @abstractmethod
    def name(self) -> Union[str, None]:
        pass

    @property
    @abstractmethod
    def value(self) -> Union[str, None]:
        pass


class BlankLine(OVPNConfigParam):
    def write(self, f_out: TextIO) -> int:
        f_out.write("\n")
        return 1

    @classmethod
    def read(cls, config: Sequence[str]) -> "BlankLine":
        if config[0].strip() != "":
            raise ValueError("Empty is not empty")

        return BlankLine()

    def __len__(self) -> int:
        return 1

    @property
    def name(self) -> None:
        return None

    @property
    def value(self) -> None:
        return None


class Comment(OVPNConfigParam):
    def __init__(self, comment: str) -> None:
        self.comment = comment

    def write(self, f_out: TextIO) -> int:
        f_out.write(f"{self.comment}\n")
        return len(self)

    @classmethod
    def read(cls, config: Sequence[str]) -> "Comment":
        line = config[0].strip()
        if not (line.startswith("#") or line.startswith(";")):
            raise ValueError("Line does not start with a comment character")

        return Comment(line)

    def __len__(self) -> int:
        return 1

    @property
    def name(self) -> str:
        return self.comment

    @property
    def value(self) -> None:
        return None


class Inline(OVPNConfigParam):
    def __init__(self, param: str, value: Sequence[str]) -> None:
        self._name = param
        self._value = value

    def write(self, f_out: TextIO) -> int:
        naked_name = self._name[1:-1]
        f_out.write(f"<{naked_name}>\n")
        for line in self._value:
            f_out.write(f"{line}\n")
        f_out.write(f"</{naked_name}>\n")

        return len(self)

    @classmethod
    def read(cls, config: Sequence[str]) -> "Inline":
        line = config[0].strip()

        if line not in INLINE_TAGS:
            raise ValueError(f"{line} is not a recognized inline tag")

        param = line
        stripped_param = line[1:-1]
        value = []

        for line in config[1:]:
            if line.strip() == f"</{stripped_param}>":
                break
            value.append(line.strip())
        else:
            raise ValueError("Tag was never closed")

        return Inline(param, value)

    def __len__(self) -> int:
        return 2 + len(self._value)

    @property
    def name(self) -> str:
        return self._name

    @property
    def value(self) -> str:
        return "\n".join(self._value)


class Parameter(OVPNConfigParam):
    def __init__(self, param: str, value: Optional[str] = None) -> None:
        self._name = param
        self._value = value

    def write(self, f_out: TextIO) -> int:
        if self._value:
            f_out.write(f"{self._name} {self._value}\n")
        else:
            f_out.write(f"{self._name}\n")
        return 1

    @classmethod
    def read(cls, config: Sequence[str]) -> "Parameter":
        line = config[0].strip()
        try:
            param, value = line.split(" ", maxsplit=1)
            return Parameter(param, value)
        except ValueError:
            return Parameter(line, None)

    def __len__(self) -> int:
        return 1

    @property
    def name(self) -> str:
        return self._name

    @property
    def value(self) -> Optional[str]:
        return self._value


class OVPNConfig:
    def __init__(self) -> None:
        self.params: List[OVPNConfigParam] = []

    @classmethod
    def read(cls, config_file: Path) -> "OVPNConfig":
        config = OVPNConfig()

        with config_file.open("rt") as f_in:
            lines = f_in.readlines()

        while lines:
            # Parameter must be at the end as it has no value checking
            for parser in [BlankLine, Comment, Inline, Parameter]:
                try:
                    # mypy does not deal with abstract class methods well, see mypy issue #6244
                    ele = parser.read(lines)  # type: ignore[attr-defined]
                    config.add(ele)
                    lines = lines[len(ele) :]
                    break
                except ValueError:
                    pass
            else:
                raise ValueError(f"Unknown config file line {lines[0]} in {config_file}")

        return config

    def add(self, new_param: OVPNConfigParam, exist_ok: bool = False) -> None:
        if new_param.name:
            for i, existing in enumerate(self.params):
                if existing.name == new_param.name:
                    if exist_ok:
                        self.params[i] = new_param
                        break
                    else:
                        raise KeyError(f"{new_param.name} already present in config")
            else:
                self.params.append(new_param)
        else:
            self.params.append(new_param)

    def write(self, out_file: Path) -> None:
        with out_file.open("wt") as f_out:
            for param in self.params:
                param.write(f_out)

    def __contains__(self, key: str) -> bool:
        for param in self.params:
            if key == param.name:
                return True
        else:
            return False

    def __getitem__(self, key: Union[str, int]) -> OVPNConfigParam:
        if isinstance(key, int):
            return self.params[key]
        elif not key:
            raise ValueError("Empty key not allowed")

        for param in self.params:
            if key == param.name:
                return param
        else:
            raise KeyError(f"{key} does not exist")

    def __delitem__(self, key: Union[str, int]) -> bool:
        if isinstance(key, int):
            del self.params[key]
            return True
        elif not key:
            raise ValueError("Empty key not allowed")

        for i, param in enumerate(self.params):
            if key == param.name:
                del self.params[i]
                return True
        else:
            raise KeyError(f"{key} does not exist")

    def index(self, key: str, start: Optional[int] = None, end: Optional[int] = None) -> int:
        if not key:
            raise ValueError("Empty key not allowed")

        start = start or 0
        end = end or len(self.params)

        for i, param in enumerate(self.params[start:end]):
            if key == param.name:
                return i
        else:
            raise ValueError(f"{key} does not exist")

    def insert(self, index: int, param: OVPNConfigParam) -> None:
        if param.name and not isinstance(param, Comment) and param.name in self:
            raise KeyError(f"{param.name} already exists")

        self.params.insert(index, param)

    def last_before_inline(self) -> int:
        try:
            return min([i for i, param in enumerate(self.params) if param.name and param.name in INLINE_TAGS])
        except ValueError:
            return len(self.params)

    def cipher_strength(self) -> CipherStrength:
        cipher = self["cipher"].value

        if cipher and ("256" in cipher or "CHACHA20-POLY1305" in cipher):
            return CipherStrength.STRONG
        elif cipher and "192" in cipher:
            return CipherStrength.MEDIUM
        elif cipher and ("128" in cipher or "SEED-" in cipher or "SM4-" in cipher):
            return CipherStrength.ACCEPTABLE
        else:
            return CipherStrength.WEAK
