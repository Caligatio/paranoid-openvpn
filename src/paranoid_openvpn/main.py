import logging
import shutil
from pathlib import Path

from .profile_parser import BlankLine, Comment, OVPNConfig, Parameter
from .types import CipherStrength, ProviderExtensions, TLSVersion

logger = logging.getLogger(__name__)


def process_pia(config: OVPNConfig) -> None:
    cipher_strength = config.cipher_strength()

    cipher_loc = config.index("cipher")
    for param in ["cipher", "ncp-disable", "data-ciphers"]:
        try:
            del config[param]
        except KeyError:
            pass

    if cipher_strength == CipherStrength.STRONG:
        config.insert(cipher_loc, Parameter("ncp-disable"))
        config.insert(cipher_loc, Parameter("data-ciphers", "AES-256-GCM:CHACHA20-POLY1305:AES-256-CBC"))
        config.insert(cipher_loc, Parameter("cipher", "AES-256-GCM"))
    else:
        config.insert(cipher_loc, Parameter("ncp-disable"))
        config.insert(cipher_loc, Parameter("data-ciphers", "AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC"))
        config.insert(cipher_loc, Parameter("cipher", "AES-128-GCM"))


def process_profile(src: Path, dest: Path, min_tls: TLSVersion, provider_ext: ProviderExtensions) -> None:
    config = OVPNConfig.read(src)
    cipher_strength = config.cipher_strength()

    if cipher_strength in [CipherStrength.STRONG, CipherStrength.MEDIUM]:
        security_settings = {
            "tls-cipher": "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384",  # noqa: E501
            "tls-groups": "secp521r1:X448:secp384r1:secp256r1:X25519",
            "tls-ciphersuites": "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
            "tls-version-min": "{} or-highest".format(min_tls.value),
        }
    else:
        security_settings = {
            "tls-cipher": "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256",  # noqa: E501
            "tls-groups": "secp256r1:X25519",
            "tls-ciphersuites": "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256",
            "tls-version-min": "{} or-highest".format(min_tls.value),
        }

    config.insert(config.last_before_inline(), BlankLine())
    config.insert(config.last_before_inline(), Comment("# Begin Paranoid OpenVPN changes"))
    for param, value in security_settings.items():
        try:
            del config[param]
        except KeyError:
            pass

        config.insert(config.last_before_inline(), Parameter(param, value))

    config.insert(config.last_before_inline(), Comment("# End Paranoid OpenVPN changes"))
    config.insert(config.last_before_inline(), BlankLine())

    if provider_ext == ProviderExtensions.PIA:
        process_pia(config)

    config.write(dest)


def process_profiles(src: Path, dest: Path, min_tls: TLSVersion, provider_ext: ProviderExtensions) -> None:
    if src.is_file():
        dest.parent.mkdir(parents=True, exist_ok=True)
        process_profile(src, dest, min_tls, provider_ext)
    else:
        for child in src.rglob("*.*"):
            dest_file = dest / child.relative_to(src)
            dest_file.parent.mkdir(parents=True, exist_ok=True)

            if child.suffix == ".ovpn":
                process_profile(child, dest_file, min_tls, provider_ext)
            else:
                shutil.copy(child, dest_file)
