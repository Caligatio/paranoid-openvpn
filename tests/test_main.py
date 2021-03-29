from pathlib import Path

import py
import pytest
from pytest_mock import MockerFixture

from paranoid_openvpn.main import process_pia, process_profile
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


def test_process_profile_strong(tmpdir: py.path.local) -> None:
    """Test process_profile() for strong ciphers."""
    test_config = OVPNConfig([Parameter("cipher", "aes-256-cbc")])
    src_path = Path(tmpdir / "test.ovpn")
    dst_path = Path(tmpdir / "test2.ovpn")

    test_config.write(src_path)
    process_profile(src_path, dst_path, TLSVersion.v1_3, ProviderExtensions.NONE)

    processed_config = OVPNConfig.read(dst_path)

    assert (
        processed_config["tls-cipher"].value
        == "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384"  # noqa: E501
    )
    assert processed_config["tls-groups"].value == "secp521r1:X448:secp384r1:secp256r1:X25519"
    assert processed_config["tls-ciphersuites"].value == "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
    assert processed_config["tls-version-min"].value == "1.3 or-highest"


def test_process_profile_not_strong(tmpdir: py.path.local) -> None:
    """Test process_profile() for not strong ciphers."""
    test_config = OVPNConfig([Parameter("cipher", "aes-128-cbc")])
    src_path = Path(tmpdir / "test.ovpn")
    dst_path = Path(tmpdir / "test2.ovpn")

    test_config.write(src_path)
    process_profile(src_path, dst_path, TLSVersion.v1_3, ProviderExtensions.NONE)

    processed_config = OVPNConfig.read(dst_path)

    assert (
        processed_config["tls-cipher"].value
        == "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256"  # noqa: E501
    )
    assert processed_config["tls-groups"].value == "secp256r1:X25519"
    assert processed_config["tls-ciphersuites"].value == "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"
    assert processed_config["tls-version-min"].value == "1.3 or-highest"


def test_process_profile_warning_weak(tmpdir: py.path.local) -> None:
    """Test process_profile() to ensure warning is emitted for weak ciphers."""
    test_config = OVPNConfig([Parameter("cipher", "bf-cbc")])
    src_path = Path(tmpdir / "test.ovpn")
    dst_path = Path(tmpdir / "test2.ovpn")

    test_config.write(src_path)

    with pytest.warns(UserWarning, match="has WEAK cipher strength!"):
        process_profile(src_path, dst_path, TLSVersion.v1_3, ProviderExtensions.NONE)


def test_process_profile_pia(mocker: MockerFixture, tmpdir: py.path.local) -> None:
    """Test process_profile() with PIA flag."""
    process_pia_spy = mocker.patch("paranoid_openvpn.main.process_pia", wraps=process_pia)
    test_config = OVPNConfig([Parameter("cipher", "aes-256-cbc")])
    src_path = Path(tmpdir / "test.ovpn")
    dst_path = Path(tmpdir / "test2.ovpn")

    test_config.write(src_path)

    process_profile(src_path, dst_path, TLSVersion.v1_3, ProviderExtensions.PIA)
    processed_config = OVPNConfig.read(dst_path)

    process_pia_spy.assert_called()

    assert (
        processed_config["tls-cipher"].value
        == "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384"  # noqa: E501
    )
    assert processed_config["tls-groups"].value == "secp521r1:X448:secp384r1:secp256r1:X25519"
    assert processed_config["tls-ciphersuites"].value == "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
    assert processed_config["tls-version-min"].value == "1.3 or-highest"
    assert processed_config["cipher"].value == "AES-256-GCM"
    assert "ncp-disable" in processed_config
    assert processed_config["data-ciphers"].value == "AES-256-GCM:CHACHA20-POLY1305:AES-256-CBC"
