import io
import sys
from pathlib import Path

import py
import pytest

from paranoid_openvpn import profile_parser, types

if sys.version_info >= (3, 8):
    from typing import Final
else:
    from typing_extensions import Final


INLINE_TAGS: Final = {
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
    "<http-proxy-user-pass>",
}

TEST_DIR = Path(__file__).resolve().parent


def test_blankline_constructor() -> None:
    """Test BlankLine's constructor."""
    blank = profile_parser.BlankLine()
    assert blank.name is None
    assert blank.value is None


def test_blankline_read_failure() -> None:
    """Test BlankLine.read() failure."""
    with pytest.raises(ValueError, match="Line is not empty"):
        profile_parser.BlankLine.read(["# Not empty"])


def test_blankline_read() -> None:
    """Test BlankLine.read()."""
    blank = profile_parser.BlankLine.read([""])
    assert blank.name is None
    assert blank.value is None


def test_blankline_write() -> None:
    """Test BlankLine.write()."""
    blank = profile_parser.BlankLine()
    dummy_io = io.StringIO()
    assert blank.write(dummy_io) == 1
    assert dummy_io.getvalue() == "\n"


def test_blankline___len__() -> None:
    """Test BlankLine.__len__()."""
    blank = profile_parser.BlankLine()
    assert len(blank) == 1


def test_comment_constructor() -> None:
    """Test Comments's constructor."""
    comment = profile_parser.Comment("# This is a comment")

    assert comment.name == "# This is a comment"
    assert comment.value is None


def test_comment_read_failure() -> None:
    """Test Comment.read() failure."""
    with pytest.raises(ValueError, match="Line does not start with a comment character"):
        profile_parser.Comment.read(["This is not a comment"])


def test_comment_read() -> None:
    """Test Comment.read()."""
    comment = profile_parser.Comment.read(["# This is a comment"])

    assert comment.name == "# This is a comment"
    assert comment.value is None


def test_comment_write() -> None:
    """Test Comment.write()."""
    comment = profile_parser.Comment("# This is a comment")

    dummy_io = io.StringIO()
    assert comment.write(dummy_io) == 1
    assert dummy_io.getvalue() == "# This is a comment\n"


def test_comment___len__() -> None:
    """Test Comment.__len__()."""
    comment = profile_parser.Comment("# This is a comment")
    assert len(comment) == 1


def test_inline_constructor() -> None:
    """Test Inline's constructor."""
    contents = ["Line 1", "Line 2\n"]
    inline = profile_parser.Inline("<ca>", contents)

    assert inline.name == "<ca>"
    assert inline.value == "Line 1\nLine 2"


def test_inline_read_failure() -> None:
    """Test Inline.read() failure."""
    with pytest.raises(ValueError, match="Line is not an inline tag: client"):
        # Test for missing/malformed close tag
        profile_parser.Inline.read(["client"])

    with pytest.raises(ValueError, match="Tag was never closed"):
        # Test for missing/malformed close tag
        profile_parser.Inline.read(["<ca>", "</ca"])


def test_inline_read() -> None:
    """Test Inline.read()."""
    for tag in INLINE_TAGS:
        close_tag = "</{}".format(tag[1:])
        content = [tag, "Line 1", "Line 2\n", close_tag]

        inline = profile_parser.Inline.read(content)
        assert inline.name == tag
        assert inline.value == "Line 1\nLine 2"


def test_inline_write() -> None:
    """Test Inline.write()."""
    contents = ["Line 1", "Line 2\n"]
    inline = profile_parser.Inline("<ca>", contents)

    dummy_io = io.StringIO()
    assert inline.write(dummy_io) == 4
    assert dummy_io.getvalue() == "<ca>\nLine 1\nLine 2\n</ca>\n"


def test_inline___len__() -> None:
    """Test Inline.__len__()."""
    contents = ["Line 1", "Line 2\n"]
    inline = profile_parser.Inline("<ca>", contents)

    assert len(inline) == 4


def test_parameter_constructor() -> None:
    """Test Parameter's constructor."""
    solo_param = profile_parser.Parameter("client")

    assert solo_param.name == "client"
    assert solo_param.value is None

    double_param = profile_parser.Parameter("dev", "tun")

    assert double_param.name == "dev"
    assert double_param.value == "tun"


def test_parameter_read_failure() -> None:
    """Test Parameter.read() failure."""
    with pytest.raises(ValueError, match="Line is not a parameter: <inline_tag>"):
        profile_parser.Parameter.read(["<inline_tag>"])

    with pytest.raises(ValueError, match="Line is not a parameter: # Comment"):
        profile_parser.Parameter.read(["# Comment"])

    with pytest.raises(ValueError, match="Line is not a parameter: ; Comment"):
        profile_parser.Parameter.read(["; Comment"])

    with pytest.raises(ValueError, match="Line is not a parameter: "):
        profile_parser.Parameter.read(["\n"])


def test_parameter_read() -> None:
    """Test Parameter.read()."""
    tests = [
        ("client", "client", None),
        ("dev tun\n", "dev", "tun"),
        ("remote server 1194", "remote", "server 1194"),
    ]

    for config_line, name, value in tests:
        param = profile_parser.Parameter.read([config_line])
        assert param.name == name
        assert param.value == value


def test_parameter_write() -> None:
    """Test Parameter.write()."""
    solo_param = profile_parser.Parameter("client")
    dummy_io = io.StringIO()
    assert solo_param.write(dummy_io) == 1
    assert dummy_io.getvalue() == "client\n"

    double_param = profile_parser.Parameter("dev", "tun")
    dummy_io = io.StringIO()
    assert double_param.write(dummy_io) == 1
    assert dummy_io.getvalue() == "dev tun\n"


def test_parameter___len__() -> None:
    """Test Parameter.__len__()."""
    param = profile_parser.Parameter("client")
    assert len(param) == 1


def test_ovpnconfig_constructor() -> None:
    """Test OVPNConfig's constructor."""
    config = profile_parser.OVPNConfig()
    assert config.params == []

    params = [profile_parser.Parameter("cipher", "AES-256-CBC"), profile_parser.Parameter("hash", "sha256")]
    config = profile_parser.OVPNConfig(params)
    assert config.params == params


def test_ovpnconfig_read(tmpdir: py.path.local) -> None:
    """Test OVPNConfig.read()."""
    simple_config = [profile_parser.Comment("# Line 1"), profile_parser.Parameter("client")]

    config_lines = ["# Line 1", "client"]

    temp_file = Path(tmpdir / "temp.ovpn")
    with temp_file.open("wt") as f_out:
        f_out.write("\n".join(config_lines))

    config = profile_parser.OVPNConfig.read(temp_file)
    assert config.params == simple_config

    config_lines.append("-bogus-")

    temp_file = Path(tmpdir / "temp.ovpn")
    with temp_file.open("wt") as f_out:
        f_out.write("\n".join(config_lines))

    with pytest.raises(ValueError, match="Unknown config file line"):
        profile_parser.OVPNConfig.read(temp_file)


def test_ovpnconfig_add() -> None:
    """Test OVPNConfig.add()."""
    cipher = profile_parser.Parameter("cipher", "AES-256-CBC")
    config = profile_parser.OVPNConfig()
    config.add(cipher)

    assert config.params == [cipher]

    # Test replacement
    cipher2 = profile_parser.Parameter("cipher", "AES-128-CBC")
    config.add(cipher2, exist_ok=True)

    assert config.params == [cipher2]

    # Test error when duplicate key inserted
    with pytest.raises(KeyError, match="cipher already present in config"):
        config.add(cipher2)

    # Duplicate blank lines should be fine
    config.add(profile_parser.BlankLine())
    config.add(profile_parser.BlankLine())

    # Duplicate comments should be fine
    config.add(profile_parser.Comment("# Comment"))
    config.add(profile_parser.Comment("# Comment"))


def test_ovpnconfig_write(tmpdir: py.path.local) -> None:
    """Test OVPNConfig.write()."""
    config = profile_parser.OVPNConfig(
        [
            profile_parser.Comment("# First line"),
            profile_parser.BlankLine(),
            profile_parser.Parameter("cipher", "AES-256-CBC"),
            profile_parser.Parameter("hash", "sha256"),
        ]
    )

    out_file = Path(tmpdir / "test.ovpn")
    config.write(out_file)

    with out_file.open("rt") as f_in:
        contents = f_in.read()

    assert contents == ("# First line\n" "\n" "cipher AES-256-CBC\n" "hash sha256\n")


def test_ovpnconfig___contains__() -> None:
    """Test OVPNConfig.__contains__()."""
    config = profile_parser.OVPNConfig([profile_parser.Parameter("cipher", "AES-256-CBC")])

    assert "cipher" in config
    assert "hash" not in config

    with pytest.raises(TypeError, match="key must be a str"):
        assert 0 not in config  # type: ignore


def test_ovpnconfig___getitem__() -> None:
    """Test OVPNConfig.__getitem__()."""
    param = profile_parser.Parameter("cipher", "AES-256-CBC")
    config = profile_parser.OVPNConfig([param])

    assert config["cipher"] == config[0] == param

    with pytest.raises(KeyError, match="hash does not exist"):
        config["hash"]

    with pytest.raises(TypeError, match="Empty key not allowed"):
        config[None]  # type: ignore


def test_ovpnconfig___delitem__() -> None:
    """Test OVPNConfig.__delitem__()."""
    params = [profile_parser.Parameter("cipher", "AES-256-CBC"), profile_parser.Parameter("hash", "sha256")]
    config = profile_parser.OVPNConfig(params)

    del config["hash"]
    assert "hash" not in config
    del config[0]
    assert "cipher" not in config

    with pytest.raises(KeyError, match="dummy does not exist"):
        del config["dummy"]

    with pytest.raises(TypeError, match="Empty key not allowed"):
        del config[None]  # type: ignore


def test_ovpnconfig_index() -> None:
    """Test OVPNConfig.index()."""
    params = [profile_parser.Parameter("cipher", "AES-256-CBC"), profile_parser.Parameter("hash", "sha256")]
    config = profile_parser.OVPNConfig(params)

    assert config.index("cipher") == 0

    with pytest.raises(KeyError, match="dummy does not exist"):
        config.index("dummy")

    with pytest.raises(TypeError, match="Empty key not allowed"):
        config.index(None)  # type: ignore


def test_ovpnconfig_insert() -> None:
    """Test OVPNConfig.insert()."""
    config = profile_parser.OVPNConfig([profile_parser.Parameter("cipher", "AES-256-CBC")])
    param = profile_parser.Parameter("hash", "sha256")

    config.insert(1, param)
    assert "hash" in config

    with pytest.raises(KeyError, match="hash already exists"):
        config.insert(2, param)


def test_ovpnconfig_last_before_inline() -> None:
    """Test OVPNConfig.last_before_inline()."""
    contents = ["Line 1", "Line 2\n"]
    inline = profile_parser.Inline("<ca>", contents)
    comment = profile_parser.Comment("# This is the first line")

    config = profile_parser.OVPNConfig([comment, inline])
    assert config.last_before_inline() == 1

    config = profile_parser.OVPNConfig([comment])
    assert config.last_before_inline() == 1


def test_ovpnconfig_cipher_strength() -> None:
    """Test OVPNConfig.cipher_strength()."""
    config = profile_parser.OVPNConfig([profile_parser.Parameter("cipher", "AES-256-CBC")])
    assert config.cipher_strength() == types.CipherStrength.STRONG

    config = profile_parser.OVPNConfig([profile_parser.Parameter("cipher", "AES-192-CBC")])
    assert config.cipher_strength() == types.CipherStrength.MEDIUM

    config = profile_parser.OVPNConfig([profile_parser.Parameter("cipher", "AES-128-CBC")])
    assert config.cipher_strength() == types.CipherStrength.ACCEPTABLE

    config = profile_parser.OVPNConfig([profile_parser.Parameter("cipher", "BF-CBC")])
    assert config.cipher_strength() == types.CipherStrength.WEAK


def test_ovpnconfigparam_cmp_error() -> None:
    """Test OVPNParam.__eq__()."""
    comment = profile_parser.Comment("# This is the first line")

    assert comment != 0
