from pathlib import Path
from zipfile import BadZipFile, ZipFile

import py
import pytest
from pytest_mock import MockerFixture

from paranoid_openvpn.input_handlers import HandleDownload, HandleZip, ResolveSource


def test_resolvesource_local_dir(mocker: MockerFixture, tmpdir: py.path.local) -> None:
    """Test ResolveSource context manager when input is a local directory."""
    mocked_handledownload = mocker.patch("paranoid_openvpn.input_handlers.HandleDownload")
    mocked_handlezip = mocker.patch("paranoid_openvpn.input_handlers.HandleZip")
    tmpdir = Path(tmpdir)

    with ResolveSource(tmpdir) as resolved_src:
        assert resolved_src == Path(tmpdir)
        assert not mocked_handledownload.called
        assert not mocked_handlezip.called

    assert tmpdir.exists()


def test_resolvesource_local_dir_as_str(mocker: MockerFixture, tmpdir: py.path.local) -> None:
    """Test ResolveSource context manager when input is a local directory as a str."""
    tmpdir = Path(tmpdir)

    with ResolveSource(str(tmpdir)) as resolved_src:
        assert resolved_src == Path(tmpdir)

    assert tmpdir.exists()


def test_resolvesource_local_nonzip_file(mocker: MockerFixture, tmpdir: py.path.local) -> None:
    """Test ResolveSource context manager when input is a local non-zip file."""
    dummy_file = Path(tmpdir / "test.ovpn")

    dummy_file.touch()

    with ResolveSource(dummy_file) as resolved_src:
        assert resolved_src == dummy_file

    assert dummy_file.exists()


def test_resolvesource_failure_badpath() -> None:
    """Test ResolveSource context manager when input is a non-existent file."""
    with pytest.raises(ValueError, match="Path does not exist"):
        with ResolveSource(Path("bad_path")):
            pass


def test_resolvesource_failure_badurn() -> None:
    """Test ResolveSource context manager when input is a bad URN."""
    with pytest.raises(ValueError, match=r"Only HTTP\(S\) supported as remote protocol"):
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


def test_handlezip(tmpdir: py.path.local) -> None:
    """Test HandleZip correct operation."""
    zip_loc = Path(tmpdir / "test.zip")
    content = "This is a test"

    with ZipFile(zip_loc, mode="w") as temp_zip:
        temp_zip.writestr("test.txt", content)

    with HandleZip(zip_loc) as extracted_dir:
        extracted_file = extracted_dir / "test.txt"
        assert extracted_file.is_file()

        with extracted_file.open("rt") as f_in:
            assert content == f_in.read()

    assert not extracted_dir.exists()


def test_handlezip_error_badzip(tmpdir: py.path.local) -> None:
    """Test HandleZip error when file is not a zip."""
    zip_loc = Path(tmpdir / "test.zip")
    content = "This is a test"

    with zip_loc.open("wt") as f_out:
        f_out.write(content)

    with pytest.raises(BadZipFile, match="File is not a zip file"):
        with HandleZip(zip_loc):
            pass


def test_handledownload(mocker: MockerFixture) -> None:
    """Test HandleDownload correct operation."""
    mocked_urllib = mocker.patch("urllib.request.urlopen")
    mocked_urllib.return_value.code = 200

    contents = b"This is a test"
    mocked_urllib.return_value.read.side_effect = [contents, b""]

    with HandleDownload("https://does_not_matter") as download:
        with download.open("rb") as f_in:
            assert contents == f_in.read()

    assert not download.exists()


def test_handledownload_error_not_http(mocker: MockerFixture) -> None:
    """Test HandleDownload error when the protocol isn't HTTP(S)."""
    with pytest.raises(ValueError, match="Can only download files via HTTP"):
        with HandleDownload("ftp://does_not_matter"):
            pass


def test_handledownload_error_http404(mocker: MockerFixture) -> None:
    """Test HandleDownload error when a HTTP non-200 code is returned."""
    mocked_urllib = mocker.patch("urllib.request.urlopen")
    mocked_urllib.return_value.code = 404

    with pytest.raises(ValueError, match="Could not download remote file, HTTP error code: 404"):
        with HandleDownload("https://does_not_matter"):
            pass


def test_handledownload_http_insecure(mocker: MockerFixture) -> None:
    """Test HandleDownload warning when insecure HTTP is used."""
    mocked_urllib = mocker.patch("urllib.request.urlopen")
    mocked_urllib.return_value.code = 200
    contents = b"This is a test"
    mocked_urllib.return_value.read.side_effect = [contents, b""]

    with pytest.warns(UserWarning, match="Downloading OpenVPN profiles over insecure connection"):
        with HandleDownload("http://does_not_matter"):
            pass


def test_handledownload_error_reading(mocker: MockerFixture) -> None:
    """Test HandleDownload error when read throws an exception."""
    mocked_urllib = mocker.patch("urllib.request.urlopen")
    mocked_urllib.return_value.code = 200
    exc_contents = "Test contents"
    mocked_urllib.return_value.read.side_effect = Exception(exc_contents)

    with pytest.raises(Exception, match=exc_contents):
        with HandleDownload("https://does_not_matter"):
            pass
