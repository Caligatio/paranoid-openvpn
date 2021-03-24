import io
import sys

import pytest

from paranoid_openvpn import profile_parser

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


def test_blankline() -> None:
    """Test correct operation of BlankLine."""
    with pytest.raises(ValueError, match="Line is not empty"):
        profile_parser.BlankLine.read(["# Not empty"])

    blank = profile_parser.BlankLine.read([""])
    assert blank.name is None
    assert blank.value is None

    dummy_io = io.StringIO()
    assert blank.write(dummy_io) == 1
    assert dummy_io.getvalue() == "\n"

    assert len(blank) == 1


def test_comment() -> None:
    """Test correct operation of Comment."""
    with pytest.raises(ValueError, match="Line does not start with a comment character"):
        profile_parser.Comment.read(["This is not a comment"])

    profile_parser.Comment.read(["; Less common comment character"])
    comment = profile_parser.Comment.read(["# This is a comment"])

    assert comment.name == "# This is a comment"
    assert comment.value is None

    dummy_io = io.StringIO()
    assert comment.write(dummy_io) == 1
    assert dummy_io.getvalue() == "# This is a comment\n"

    assert len(comment) == 1


def test_inline() -> None:
    """Test correct operation of Inline."""
    with pytest.raises(ValueError, match="Line is not an inline tag: client"):
        # Test for missing/malformed close tag
        profile_parser.Inline.read(["client"])

    with pytest.raises(ValueError, match="Tag was never closed"):
        # Test for missing/malformed close tag
        profile_parser.Inline.read(["<ca>", "</ca"])

    for tag in INLINE_TAGS:
        close_tag = "</{}".format(tag[1:])
        content = [tag, "Line 1", "Line 2\n", close_tag]

        inline = profile_parser.Inline.read(content)
        assert inline.name == tag
        assert inline.value == "Line 1\nLine 2"

        dummy_io = io.StringIO()
        assert inline.write(dummy_io) == 4
        assert dummy_io.getvalue() == "{}\nLine 1\nLine 2\n{}\n".format(tag, close_tag)

        assert len(inline) == 4


def test_parameter() -> None:
    """Test correct operation of Parameter."""
    with pytest.raises(ValueError, match="Line is not a parameter: <inline_tag>"):
        profile_parser.Parameter.read(["<inline_tag>"])

    with pytest.raises(ValueError, match="Line is not a parameter: # Comment"):
        profile_parser.Parameter.read(["# Comment"])

    with pytest.raises(ValueError, match="Line is not a parameter: ; Comment"):
        profile_parser.Parameter.read(["; Comment"])

    with pytest.raises(ValueError, match="Line is not a parameter: "):
        profile_parser.Parameter.read(["\n"])

    tests = [
        ("client", "client", None),
        ("dev tun\n", "dev", "tun"),
        ("remote server 1194", "remote", "server 1194"),
    ]

    for config_line, name, value in tests:
        param = profile_parser.Parameter.read([config_line])
        assert param.name == name
        assert param.value == value

        dummy_io = io.StringIO()
        assert param.write(dummy_io) == 1
        assert dummy_io.getvalue() == "{}\n".format(config_line.strip())

        assert len(param) == 1
