import logging
import os
import re
import shutil
import sys
import tempfile
import urllib.request
import warnings
import zipfile
from contextlib import ExitStack
from pathlib import Path
from types import TracebackType
from typing import Optional, Type, Union

if sys.version_info >= (3, 8):
    from typing import Final, Literal
else:
    from typing_extensions import Final, Literal  # pragma: no cover


logger = logging.getLogger(__name__)


CHUNK_SIZE: Final = 8192


class HandleZip:
    """Context manager that transparently extracts ZIP files to a temporary location."""

    def __init__(self, src: Path) -> None:
        """Extracts the input ZIP file to a temporary location.

        :param src: Path to the input ZIP file.
        """
        self.temp_dir = Path(tempfile.mkdtemp())

        try:
            with zipfile.ZipFile(src) as f_in:
                f_in.extractall(self.temp_dir)
                logger.debug("Zip file extracted temporarily to %s", self.temp_dir)
        except Exception:
            shutil.rmtree(self.temp_dir)
            raise

    def __enter__(self) -> Path:
        """Context manager __enter__ function.

        :return: Resolved path to a local directory to process.
        """
        return self.temp_dir

    def __exit__(
        self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]
    ) -> Literal[False]:
        """Cleans up any temporary files resulting from the ZIP extraction."""
        shutil.rmtree(self.temp_dir)
        return False


class HandleDownload:
    """Context manager that transparently downloads remote files to a temporary location."""

    def __init__(self, url: str) -> None:
        """Downloads the resource given by `url`.

        :param url: URL to download.
        :raises ValueError: Raised for non-HTTP(S) URLs and if the download fails.
        """
        if not (url.startswith("http://") or url.startswith("https://")):
            raise ValueError("Can only download files via HTTP")

        if url.startswith("http://"):
            warnings.warn("Downloading OpenVPN profiles over insecure connection")

        resp = urllib.request.urlopen(url)  # noqa: S310

        if resp.code != 200:
            raise ValueError(f"Could not download remote file, HTTP error code: {resp.code}")

        fd, file_name = tempfile.mkstemp()
        os.close(fd)
        self.temp_file = Path(file_name)

        try:
            with self.temp_file.open("wb") as f_out:
                while True:
                    data = resp.read(8192)
                    f_out.write(data)
                    if len(data) != CHUNK_SIZE:
                        break

            logger.debug("Downloaded file temporarily saved at %s", self.temp_file)
        except Exception:
            self.temp_file.unlink()
            raise

    def __enter__(self) -> Path:
        """Context manager __enter__ function.

        :return: Resolved path to a local file to process or extract.
        """
        return self.temp_file

    def __exit__(
        self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]
    ) -> Literal[False]:
        """Cleans up any temporary files resulting from the download."""
        self.temp_file.unlink()
        return False


class ResolveSource:
    """Context manager that handles all the different input sources and provides a path to a local file/directory."""

    def __init__(self, src: Union[str, Path]) -> None:
        """Performs the needed combination of downloading/extracting source files.

        :param src: HTTP(S) URL or local path to the OVPN profiles to process.
        """
        self.exit_stack = ExitStack()

        src_as_str = str(src)
        if re.search(r"^[a-zA-Z0-9]+://", src_as_str):
            if src_as_str.startswith("http://") or src_as_str.startswith("https://"):
                logger.debug("Determined source was remote file, downloading")
                self.path = self.exit_stack.enter_context(HandleDownload(src_as_str))
            else:
                raise ValueError("Only HTTP(S) supported as remote protocol")
        else:
            self.path = Path(src)

        if self.path.is_file():
            try:
                self.path = self.exit_stack.enter_context(HandleZip(self.path))
            except zipfile.BadZipFile:
                # Make an assumption that our thing is a non-zip file
                pass
        elif not self.path.is_dir():
            raise ValueError("Path does not exist")

    def __enter__(self) -> Path:
        """Context manager __enter__ function.

        :return: Resolved path to either a local file or directory containing OVPN profile(s).
        """
        return self.path

    def __exit__(
        self, exc_type: Optional[Type[BaseException]], exc_val: Optional[BaseException], exc_tb: Optional[TracebackType]
    ) -> Literal[False]:
        """Cleans up all the temporary files created by calling child context managers."""
        self.exit_stack.close()
        return False
