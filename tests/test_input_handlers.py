from pathlib import Path

import py
import pytest
from pytest_mock import MockerFixture

from paranoid_openvpn.input_handlers import ResolveSource


def test_resolvesource_local_dir(mocker: MockerFixture, tmpdir: py.path.local) -> None:
    """Test ResolveSource context manager when input is a local directory."""
    mocked_handledownload = mocker.patch("paranoid_openvpn.input_handlers.HandleDownload")
    mocked_handlezip = mocker.patch("paranoid_openvpn.input_handlers.HandleZip")

    tmpdir = Path(tmpdir)

    with ResolveSource(tmpdir) as resolved_src:
        assert resolved_src == Path(tmpdir)
        assert not mocked_handledownload.called
        assert not mocked_handlezip.called


def test_resolvesource_local_nonzip_file(mocker: MockerFixture, tmpdir: py.path.local) -> None:
    """Test ResolveSource context manager when input is a local non-zip file."""
    dummy_file = Path(tmpdir / "test.ovpn")

    dummy_file.touch()

    with ResolveSource(dummy_file) as resolved_src:
        assert resolved_src == dummy_file


def test_resolvesource_failure_badpath() -> None:
    """Test ResolveSource context manager when input is a non-existent file."""
    with pytest.raises(ValueError, match="Path does not exist"):
        with ResolveSource(Path("bad_path")):
            pass


def test_resolvesource_failure_badurn() -> None:
    """Test ResolveSource context manager when input is a bad URN."""
    with pytest.raises(ValueError, match=r"src must be a HTTP\(S\) URL if a string"):
        with ResolveSource("ftp://bad_host"):
            pass


def test_resolvesource_http_nonzip(mocker: MockerFixture, tmpdir: py.path.local) -> None:
    """Test ResolveSource context manager when input is HTTP non-zip file."""
    mocked_handledownload = mocker.patch("paranoid_openvpn.input_handlers.HandleDownload")
    downloaded_path = Path(tmpdir / "dummy.ovpn")

    downloaded_path.touch()
    dummy_url = "http://does_not_matter"

    mocked_handledownload.return_value.__enter__.return_value = downloaded_path

    with ResolveSource(dummy_url) as resolved_src:
        assert resolved_src == downloaded_path
        assert mocked_handledownload.called_with(dummy_url)


def test_resolvesource_local_zip(mocker: MockerFixture, tmpdir: py.path.local) -> None:
    """Test ResolveSource context manager when input is local zip file."""
    mocked_handlezip = mocker.patch("paranoid_openvpn.input_handlers.HandleZip")
    extracted_path = Path(tmpdir)
    dummy_zip = Path(tmpdir / "dummy.zip")
    dummy_zip.touch()

    mocked_handlezip.return_value.__enter__.return_value = extracted_path

    with ResolveSource(dummy_zip) as resolved_src:
        assert resolved_src == extracted_path
        assert mocked_handlezip.called_with(dummy_zip)


def test_resolvesource_remote_zip(mocker: MockerFixture, tmpdir: py.path.local) -> None:
    """Test ResolveSource context manager when input is HTTP zip file."""
    mocked_handledownload = mocker.patch("paranoid_openvpn.input_handlers.HandleDownload")
    mocked_handlezip = mocker.patch("paranoid_openvpn.input_handlers.HandleZip")

    extracted_path = Path(tmpdir)
    dummy_zip = Path(tmpdir / "dummy.zip")
    dummy_zip.touch()
    dummy_url = "http://does_not_matter"

    mocked_handledownload.return_value.__enter__.return_value = dummy_zip
    mocked_handlezip.return_value.__enter__.return_value = extracted_path

    with ResolveSource(dummy_zip) as resolved_src:
        assert resolved_src == extracted_path
        assert mocked_handledownload.called_with(dummy_url)
        assert mocked_handlezip.called_with(dummy_zip)
