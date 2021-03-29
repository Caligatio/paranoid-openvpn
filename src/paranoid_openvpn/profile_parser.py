import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable, Optional, Sequence, TextIO, Union

from .types import CipherStrength


class OVPNConfigParam(ABC):
    """ABC that represents a single setting in an OpenVPN config. Used mostly for `typing` purposes."""

    @abstractmethod
    def write(self, f_out: TextIO) -> int:  # pragma: no cover
        """Abstract method to require children to support writing their contents to a file."""
        pass

    @classmethod
    @abstractmethod
    def read(cls, config: Sequence[str]) -> "OVPNConfigParam":  # pragma: no cover
        """Abstract method to require children to implement a factory that reads from config lines."""
        pass

    @abstractmethod
    def __len__(self) -> int:  # pragma: no cover
        """Abstract method to require children to implement support for the len() function."""
        pass

    def __eq__(self, other: object) -> bool:  # pragma: no cover
        """Returns whether this object and another `OVPNConfigParam` are equal."""
        if not isinstance(other, OVPNConfigParam):
            return NotImplemented

        return self.name == other.name and self.value == other.value

    @property
    @abstractmethod
    def name(self) -> Union[str, None]:  # pragma: no cover
        """Abstract method to require children to expose the setting's name, if applicable."""
        pass

    @property
    @abstractmethod
    def value(self) -> Union[str, None]:  # pragma: no cover
        """Abstract method to require children to expose the setting's value, if applicable."""
        pass


class BlankLine(OVPNConfigParam):
    """Class that represents a literal blank line. Need this for method compatibility."""

    def write(self, f_out: TextIO) -> int:
        """Writes a blank line to the output OVPN profile.

        :param f_out: Handle to file open for writing.
        :return: The number of lines written.
        """
        f_out.write("\n")
        return 1

    @classmethod
    def read(cls, config: Sequence[str]) -> "BlankLine":
        """Factory function that returns an instance of this class if the head of `config` is applicable.

        :raises ValueError: Raised if the first config line isn't blank.
        :return: Instance of this class initialized with the head of `config`
        """
        if config[0].strip() != "":
            raise ValueError("Line is not empty")

        return BlankLine()

    def __len__(self) -> int:
        """Returns the number of lines this element takes up."""
        return 1

    @property
    def name(self) -> None:
        """Returns None as blank lines don't have a name."""
        return None

    @property
    def value(self) -> None:
        """Returns None as blank lines don't have a value."""
        return None


class Comment(OVPNConfigParam):
    """Class represending a OVPN profile comment."""

    def __init__(self, comment: str) -> None:
        """Constructor.

        :param comment: The content of the comment, prefixed with the comment character.
        """
        self.comment = comment.strip()

    def write(self, f_out: TextIO) -> int:
        """Writes the contents of the comment to the output OVPN profile.

        :param f_out: Handle to file open for writing.
        :return: The number of lines written.
        """
        f_out.write(f"{self.comment}\n")
        return len(self)

    @classmethod
    def read(cls, config: Sequence[str]) -> "Comment":
        """Factory function that returns an instance of this class if the head of `config` is applicable.

        :raises valueerror: raised if the first config line doesn't start with a comment character
        :return: Instance of this class initialized with the head of `config`
        """
        if not (config[0].startswith("#") or config[0].startswith(";")):
            raise ValueError("Line does not start with a comment character")

        return Comment(config[0])

    def __len__(self) -> int:
        """Returns the number of lines this element takes up."""
        return 1

    @property
    def name(self) -> str:
        """Returns the content of the comment."""
        return self.comment

    @property
    def value(self) -> None:
        """Returns None as comments don't have a value."""
        return None


class Inline(OVPNConfigParam):
    """Class represending a OVPN profile inline value (e.g. ca, cert)."""

    def __init__(self, param: str, value: Sequence[str]) -> None:
        """Constructor.

        :param param: The name of the inline parameter, including <>s
        :param value: Sequence of strings that make up the inline value
        """
        self._name = param.strip()
        self._value = [item.strip() for item in value]

    def write(self, f_out: TextIO) -> int:
        """Writes the contents of the inline element to the output OVPN profile.

        :param f_out: Handle to file open for writing
        :return: The number of lines written
        """
        naked_name = self._name[1:-1]
        f_out.write(f"<{naked_name}>\n")
        for line in self._value:
            f_out.write(f"{line}\n")
        f_out.write(f"</{naked_name}>\n")

        return len(self)

    @classmethod
    def read(cls, config: Sequence[str]) -> "Inline":
        """Factory function that returns an instance of this class if the head of `config` is applicable.

        :raises ValueError: Raised if the first config line isn't an inline tag
        :return: Instance of this class initialized with the entire contents of the inline tag
        """
        line = config[0].strip()

        tag_match = re.match(r"<([a-z0-9][a-z\-\_0-9]*[a-z0-9])>", line)
        if not tag_match:
            raise ValueError(f"Line is not an inline tag: {line}")

        param = tag_match.group(0)
        stripped_param = tag_match.group(1)
        value = []

        for line in config[1:]:
            if line.startswith(f"</{stripped_param}>"):
                break
            value.append(line)
        else:
            raise ValueError("Tag was never closed")

        return Inline(param, value)

    def __len__(self) -> int:
        """Returns the number of lines this element takes up."""
        return 2 + len(self._value)

    @property
    def name(self) -> str:
        """Returns the name of the inline tag, including the <>s."""
        return self._name

    @property
    def value(self) -> str:
        """Returns the the contents of the inline tag as one string."""
        return "\n".join(self._value)


class Parameter(OVPNConfigParam):
    """Class represending a standard OVPN profile parameter."""

    def __init__(self, param: str, value: Optional[str] = None) -> None:
        """Constructor.

        :param param: Name of the parameter
        :param value: Value of the parameter, can be None for some parameters
        """
        self._name = param.strip()
        self._value = value.strip() if value else None

    def write(self, f_out: TextIO) -> int:
        """Writes the contents of the parammeter to the output OVPN profile.

        :param f_out: Handle to file open for writing.
        :return: The number of lines written.
        """
        if self._value:
            f_out.write(f"{self._name} {self._value}\n")
        else:
            f_out.write(f"{self._name}\n")
        return 1

    @classmethod
    def read(cls, config: Sequence[str]) -> "Parameter":
        """Factory function that returns an instance of this class if the head of `config` is applicable.

        :return: Instance of this class initialized with the contents of the parameter
        """
        line = config[0].strip()

        if not re.match(r"[a-z0-9][a-z\-\_0-9]*[a-z0-9]", line):
            raise ValueError(f"Line is not a parameter: {line}")

        try:
            param, value = line.split(" ", maxsplit=1)
            return Parameter(param, value)
        except ValueError:
            return Parameter(line, None)

    def __len__(self) -> int:
        """Returns the number of lines this element takes up."""
        return 1

    @property
    def name(self) -> str:
        """Returns the name of the parameter."""
        return self._name

    @property
    def value(self) -> Optional[str]:
        """Returns the name of the parameter, can be None if the parameter has no value."""
        return self._value


class OVPNConfig:
    """Class that represents an entire OVPN profile."""

    def __init__(self, params: Optional[Iterable[OVPNConfigParam]] = None) -> None:
        """Constructor."""
        self.params = list(params) if params else []

    @classmethod
    def read(cls, config_file: Path) -> "OVPNConfig":
        """Factory function that returns an instance of this class based off the `config_file` input.

        :raises ValueError: Raised if an unknown parameter is encountered
        :return: Instance of this class initialized with the entire contents of file
        """
        config = OVPNConfig()

        with config_file.open("rt") as f_in:
            lines = f_in.readlines()

        while lines:
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
        """Adds a new parameter to the config.

        If the parameter already exists and `exist_ok` is True, the old value will be replaced in place; if `exist_ok`
        is False, an KeyError will be raised.

        :param new_param: New parameter to add to the profile.
        :param exist_ok: Whether it is OK if the parameter already exists in the config.
        :raises KeyError: Raised if `new_param` already exists and `exist_ok` is False
        """
        if not (isinstance(new_param, BlankLine) or isinstance(new_param, Comment)):
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

    def write(self, out_file: Path) -> int:
        """Writes the contents of the entire config to the output OVPN profile.

        :param f_out: Handle to file open for writing.
        :return: The number of lines written.
        """
        total_lines = 0
        with out_file.open("wt") as f_out:
            for param in self.params:
                total_lines += param.write(f_out)

        return total_lines

    def __contains__(self, key: str) -> bool:
        """Magic function that implements "in"; returns whether that parameter is present in the config.

        :param key: The parameter name or comment contents
        :raises TypeError: Raise if `key` is not a str
        :return: Whether the parameter is present
        """
        if not isinstance(key, str):
            raise TypeError("key must be a str")

        for param in self.params:
            if key == param.name:
                return True
        else:
            return False

    def __getitem__(self, key: Union[str, int]) -> OVPNConfigParam:
        """Magic function that implements object dereference.

        Implements a hybrid of sequence and mapping deference. If `key` is an `int`, returns the element as if this
        was a list. If `key` is a `str`, returns the element as if this was a dictionary.

        :param key: The integer location or name of the desired parameter
        :raises TypeError: Raise if `key` is not an `int` and is Falsey
        :raises KeyError: Raised if `key` is a `str` and that element does not exist
        :return: Specified element
        """
        if isinstance(key, int):
            return self.params[key]
        elif not key:
            raise TypeError("Empty key not allowed")

        for param in self.params:
            if key == param.name:
                return param
        else:
            raise KeyError(f"{key} does not exist")

    def __delitem__(self, key: Union[str, int]) -> None:
        """Magic function that implements object deletion.

        Implements a hybrid of sequence and mapping deletion. If `key` is an `int`, deletes the element at that index.
        If `key` is a `str`, deletes that parameter by name.

        :param key: The integer location or name of the desired parameter to delete
        :raises TypeError: Raise if `key` is not an `int` and is Falsey
        :raises KeyError: Raised if `key` is a `str` and that element does not exist
        """
        if isinstance(key, int):
            del self.params[key]
            return
        elif not key:
            raise TypeError("Empty key not allowed")

        for i, param in enumerate(self.params):
            if key == param.name:
                del self.params[i]
                break
        else:
            raise KeyError(f"{key} does not exist")

    def index(self, key: str, start: Optional[int] = None, end: Optional[int] = None) -> int:
        """Implements behavior similar to `list.index()`.

        :param key: The parameter name to search for
        :param start: The minimum index to start at, defaults to the start
        :param end: The maximum index to search until (exclusive), defaults to the end
        :raises TypeError: Raised if the index is Falsey
        :raises KeyError: Raised if the key does not exist
        :return: The index of the element, if present
        """
        if not key:
            raise TypeError("Empty key not allowed")

        start = start or 0
        end = end or len(self.params)

        for i, param in enumerate(self.params[start:end]):
            if key == param.name:
                return i
        else:
            raise KeyError(f"{key} does not exist")

    def insert(self, index: int, param: OVPNConfigParam) -> None:
        """Implements behavior similar to `list.insert`.

        :param index: The desired index to insert at
        :param param: The new OVPN element to add
        :raises KeyError: Raise if `param` already exists
        """
        if param.name and not isinstance(param, Comment) and param.name in self:
            raise KeyError(f"{param.name} already exists")

        self.params.insert(index, param)

    def last_before_inline(self) -> int:
        """Returns the last viable line before inline elements start.

        This method is based on an assumption that inline elements are at the end of the ffile and therefore it is
        desirable to insert non-inline elements before them. It returns the last insert-able line number before
        any inline elements start.

        :return: The last line before inline elements start
        """
        try:
            return min([i for i, param in enumerate(self.params) if isinstance(param, Inline)])
        except ValueError:
            return len(self.params)

    def cipher_strength(self) -> CipherStrength:
        """Uses a dumb heuristic to determine the strength of the "cipher" in the file.

        This is not very enlightened: 256-bit -> strong, 192-bit -> medium, 128-bit -> acceptable, and everything
        else is weak. This would break if algorithms are added that don't follow these common key sizes.

        :return: Enum value that describes the cipher stregnth
        """
        cipher = self["cipher"].value.upper() if self["cipher"].value else None

        if cipher and ("256" in cipher or "CHACHA20-POLY1305" in cipher):
            return CipherStrength.STRONG
        elif cipher and "192" in cipher:
            return CipherStrength.MEDIUM
        elif cipher and ("128" in cipher or "SEED-" in cipher or "SM4-" in cipher):
            return CipherStrength.ACCEPTABLE
        else:
            return CipherStrength.WEAK
