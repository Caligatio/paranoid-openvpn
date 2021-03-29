import sys
from pathlib import Path

import py
import pytest
from pytest_mock import MockerFixture

from paranoid_openvpn.cli import cli
from paranoid_openvpn.types import ProviderExtensions, TLSVersion


def test_cli_no_flags(mocker: MockerFixture, tmpdir: py.path.local) -> None:
    """Test emulated command-line call with no extra flags."""
    process_profiles = mocker.patch("paranoid_openvpn.cli.process_profiles")

    sys.argv = ["cli_name", str(tmpdir), "dest"]

    with pytest.raises(SystemExit) as exc:
        cli()

    assert exc.value.code == 0

    process_profiles.assert_called_once_with(tmpdir, Path("dest"), TLSVersion.v1_3, ProviderExtensions.NONE)


def test_cli_with_pia(mocker: MockerFixture, tmpdir: py.path.local) -> None:
    """Test emulated command-line call with --pia flag."""
    process_profiles = mocker.patch("paranoid_openvpn.cli.process_profiles")

    sys.argv = ["cli_name", str(tmpdir), "dest", "--pia"]

    with pytest.raises(SystemExit) as exc:
        cli()

    assert exc.value.code == 0

    process_profiles.assert_called_once_with(tmpdir, Path("dest"), TLSVersion.v1_3, ProviderExtensions.PIA)


def test_cli_with_tls(mocker: MockerFixture, tmpdir: py.path.local) -> None:
    """Test emulated command-line call with --min-tls flag."""
    process_profiles = mocker.patch("paranoid_openvpn.cli.process_profiles")

    sys.argv = ["cli_name", str(tmpdir), "dest", "--min-tls", "1.2"]

    with pytest.raises(SystemExit) as exc:
        cli()

    assert exc.value.code == 0

    process_profiles.assert_called_once_with(tmpdir, Path("dest"), TLSVersion.v1_2, ProviderExtensions.NONE)


def test_cli_error_badpath(tmpdir: py.path.local) -> None:
    """Test emulated command-line call with non-existent local resource."""
    sys.argv = ["cli_name", str(tmpdir / "in"), "dest"]

    with pytest.raises(SystemExit) as exc:
        cli()

    assert exc.value.code == 1
