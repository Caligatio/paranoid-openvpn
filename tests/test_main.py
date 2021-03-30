from pathlib import Path

import py
import pytest
from pytest_mock import MockerFixture

from paranoid_openvpn.main import process_pia, process_profile, process_profiles
from paranoid_openvpn.profile_parser import OVPNConfig, Parameter
from paranoid_openvpn.types import ProviderExtensions, TLSVersion


def test_process_pia_strong() -> None:
    """Test process_pia() for strong ciphers."""
    test_config = OVPNConfig([Parameter("cipher", "AES-256-CBC")])

    process_pia(test_config)

    assert test_config["cipher"].value == "AES-256-GCM"
    assert "ncp-disable" in test_config
    assert test_config["data-ciphers"].value == "AES-256-GCM:CHACHA20-POLY1305:AES-256-CBC"


def test_process_pia_not_strong() -> None:
    """Test process_pia() for not strong ciphers."""
    test_config = OVPNConfig([Parameter("cipher", "AES-128-CBC")])

    process_pia(test_config)

    assert test_config["cipher"].value == "AES-128-GCM"
    assert "ncp-disable" in test_config
    assert test_config["data-ciphers"].value == "AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC"


def test_process_profile_strong() -> None:
    """Test process_profile() for strong ciphers."""
    test_config = OVPNConfig([Parameter("cipher", "aes-256-cbc")])

    process_profile(test_config, TLSVersion.v1_3, ProviderExtensions.NONE)

    assert (
        test_config["tls-cipher"].value
        == "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384"  # noqa: E501
    )
    assert test_config["tls-groups"].value == "secp521r1:X448:secp384r1:secp256r1:X25519"
    assert test_config["tls-ciphersuites"].value == "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
    assert test_config["tls-version-min"].value == "1.3 or-highest"


def test_process_profile_not_strong() -> None:
    """Test process_profile() for not strong ciphers."""
    test_config = OVPNConfig([Parameter("cipher", "aes-128-cbc")])

    process_profile(test_config, TLSVersion.v1_3, ProviderExtensions.NONE)

    assert (
        test_config["tls-cipher"].value
        == "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256"  # noqa: E501
    )
    assert test_config["tls-groups"].value == "secp256r1:X25519"
    assert test_config["tls-ciphersuites"].value == "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"
    assert test_config["tls-version-min"].value == "1.3 or-highest"


def test_process_profile_warning_weak(tmpdir: py.path.local) -> None:
    """Test process_profile() to ensure warning is emitted for weak ciphers."""
    with pytest.warns(UserWarning, match="has WEAK cipher strength!"):
        test_config = OVPNConfig([Parameter("cipher", "bf-cbc")])
        process_profile(test_config, TLSVersion.v1_3, ProviderExtensions.NONE)


def test_process_profile_pia(mocker: MockerFixture) -> None:
    """Test process_profile() with PIA flag."""
    process_pia_spy = mocker.patch("paranoid_openvpn.main.process_pia", wraps=process_pia)
    test_config = OVPNConfig([Parameter("cipher", "aes-256-cbc")])

    process_profile(test_config, TLSVersion.v1_3, ProviderExtensions.PIA)

    process_pia_spy.assert_called()

    assert (
        test_config["tls-cipher"].value
        == "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384"  # noqa: E501
    )
    assert test_config["tls-groups"].value == "secp521r1:X448:secp384r1:secp256r1:X25519"
    assert test_config["tls-ciphersuites"].value == "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
    assert test_config["tls-version-min"].value == "1.3 or-highest"
    assert test_config["cipher"].value == "AES-256-GCM"
    assert "ncp-disable" in test_config
    assert test_config["data-ciphers"].value == "AES-256-GCM:CHACHA20-POLY1305:AES-256-CBC"


def test_process_profiles_file(tmpdir: py.path.local) -> None:
    """Test process_profiles() with a single file input."""
    test_config = OVPNConfig([Parameter("cipher", "aes-256-cbc")])
    test_file = Path(tmpdir / "test.ovpn")
    out_file = Path(tmpdir / "out" / "test.opvpn")

    test_config.write(test_file)

    process_profiles(test_file, out_file, TLSVersion.v1_3, ProviderExtensions.NONE)

    out_config = OVPNConfig.read(out_file)

    assert (
        out_config["tls-cipher"].value
        == "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384"  # noqa: E501
    )
    assert out_config["tls-groups"].value == "secp521r1:X448:secp384r1:secp256r1:X25519"
    assert out_config["tls-ciphersuites"].value == "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
    assert out_config["tls-version-min"].value == "1.3 or-highest"


def test_process_profiles_error_badpath(tmpdir: py.path.local) -> None:
    """Test process_profiles() raising an exception when the source does not exist."""
    test_file = Path(tmpdir / "test.ovpn")
    out_file = Path(tmpdir / "test_out.ovpn")

    with pytest.raises(ValueError, match="Source does not exist"):
        process_profiles(test_file, out_file, TLSVersion.v1_3, ProviderExtensions.NONE)


def test_process_profiles_dir(mocker: MockerFixture, tmpdir: py.path.local) -> None:
    """Test process_profiles() with a directory input."""
    mock_process_profile = mocker.patch("paranoid_openvpn.main.process_profile")

    test_dir = Path(tmpdir / "in")
    test_dir.mkdir()

    out_dir = Path(tmpdir / "out")

    (test_dir / "test1.ovpn").touch()
    (test_dir / "test2.ovpn").touch()
    (test_dir / "other.pem").touch()

    process_profiles(test_dir, out_dir, TLSVersion.v1_3, ProviderExtensions.NONE)

    assert (out_dir / "test1.ovpn").is_file()
    assert (out_dir / "test2.ovpn").is_file()
    assert (out_dir / "other.pem").is_file()

    assert mock_process_profile.call_count == 2


def test_process_profiles_error_nested_src_dst(tmpdir: py.path.local) -> None:
    """Test process_profiles() raising an exception when dest is subdir of source."""
    out_dir = Path(tmpdir / "out")

    with pytest.raises(ValueError, match="dest path cannot be relative to src path"):
        process_profiles(Path(tmpdir), out_dir, TLSVersion.v1_3, ProviderExtensions.NONE)
