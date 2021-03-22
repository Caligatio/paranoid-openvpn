import logging
import shutil
import sys
from pathlib import Path
from typing import Dict, Optional

from .types import TLSVersion

if sys.version_info >= (3, 8):
    from typing import Final
else:
    from typing_extensions import Final

logger = logging.getLogger(__name__)


def process_profile(src: Path, dest: Path, min_tls: TLSVersion) -> None:
    security_settings: Final = {
        "tls-cipher": "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384",  # noqa: E501
        "tls-groups": "secp521r1:X448:secp384r1:secp256r1:X25519",
        "tls-ciphersuites": "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
        "tls-version-min": "{} or-highest".format(min_tls.value),
        "tls-version-max": "1.3",
    }

    with src.open("r") as f_in, dest.open("w") as f_out:
        lines = f_in.readlines()
        num_lines = len(lines)
        insert_points: Dict[str, Optional[int]] = {
            "tls-version-min": None,
            "tls-version-max": None,
            "tls-cipher": None,
            "tls-ciphersuites": None,
            "tls-groups": None,
        }
        block_points = {
            "<crl-verify>": num_lines,
            "<cert>": num_lines,
            "<ca>": num_lines,
            "<key>": num_lines,
            "<tls-auth>": num_lines,
            "<dh>": num_lines,
            "<extra-certs>": num_lines,
            "<pkcs12>": num_lines,
            "<secret>": num_lines,
            "<tls-crypt>": num_lines,
            "<htt-proxy-user-pass>": num_lines,
        }

        for line_num, line in enumerate(lines):
            for key in insert_points:
                if line.startswith(key):
                    insert_points[key] = line_num
                    break
            for key in block_points:
                if line.startswith(key):
                    block_points[key] = line_num
                    break

        last_nonblock = min(block_points.values())

        for param in ("tls-groups", "tls-cipher", "tls-ciphersuites", "tls-version-max", "tls-version-min"):
            insert_point = insert_points[param]
            if insert_point is not None:
                lines[insert_point] = "{} {}\n".format(param, security_settings[param])
            else:
                lines.insert(last_nonblock, "{} {}\n".format(param, security_settings[param]))

        f_out.writelines(lines)


def process_profiles(src: Path, dest: Path, min_tls: TLSVersion) -> None:
    if src.is_file():
        dest.parent.mkdir(parents=True, exist_ok=True)
        process_profile(src, dest, min_tls)
    else:
        for child in src.rglob("*.*"):
            dest_file = dest / child.relative_to(src)
            dest_file.parent.mkdir(parents=True, exist_ok=True)

            if child.suffix == ".ovpn":
                process_profile(child, dest_file, min_tls)
            else:
                shutil.copy(child, dest_file)
