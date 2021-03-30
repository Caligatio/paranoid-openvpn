import logging
import shutil
import warnings
from pathlib import Path

from .profile_parser import BlankLine, Comment, OVPNConfig, Parameter
from .types import CipherStrength, ProviderExtensions, TLSVersion

logger = logging.getLogger(__name__)


def process_pia(config: OVPNConfig) -> None:
    """Adds necessary options to force AES-GCM connections to Private Internet Access.

    :param config: The already hardened OVPN profile
    """
    cipher_strength = config.cipher_strength()

    if cipher_strength == CipherStrength.STRONG:
        cipher_settings = [
            Parameter("cipher", "AES-256-GCM"),
            Parameter("data-ciphers", "AES-256-GCM:CHACHA20-POLY1305:AES-256-CBC"),
            Parameter("ncp-disable"),
        ]
    else:
        cipher_settings = [
            Parameter("cipher", "AES-128-GCM"),
            Parameter("data-ciphers", "AES-128-GCM:CHACHA20-POLY1305:AES-128-CBC"),
            Parameter("ncp-disable"),
        ]

    lines_to_insert = [
        BlankLine(),
        Comment("# Begin Paranoid OpenVPN changes"),
        *cipher_settings,
        Comment("# End Paranoid OpenVPN changes"),
        BlankLine(),
    ]

    # Insert the cipher settings where the old cipher setting was located, also need to clear out the previous settings
    cipher_loc = config.index("cipher")
    for param in cipher_settings:
        try:
            del config[param.name]
        except KeyError:
            pass

    for i, line in enumerate(lines_to_insert, start=cipher_loc):
        config.insert(i, line)


def process_profile(config: OVPNConfig, min_tls: TLSVersion, provider_ext: ProviderExtensions) -> None:
    """Completely processes one OVPN profile.

    :param config: OVPN config to modify.
    :param min_tls: Minimum TLS version to require.
    :param provider_ext: Flag to indicate which, if any, provider specific tweaks to apply.
    """
    cipher_strength = config.cipher_strength()

    if cipher_strength in [CipherStrength.STRONG, CipherStrength.MEDIUM]:
        security_settings = [
            Parameter("tls-version-min", "{} or-highest".format(min_tls.value)),
            Parameter(
                "tls-cipher",
                "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384:TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384",  # noqa: E501
            ),
            Parameter("tls-groups", "secp521r1:X448:secp384r1:secp256r1:X25519"),
            Parameter("tls-ciphersuites", "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"),
        ]
    else:
        security_settings = [
            Parameter("tls-version-min", "{} or-highest".format(min_tls.value)),
            Parameter(
                "tls-cipher",
                "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256:TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256:TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256",  # noqa: E501
            ),
            Parameter("tls-groups", "secp256r1:X25519"),
            Parameter("tls-ciphersuites", "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"),
        ]

    lines_to_insert = [
        BlankLine(),
        Comment("# Begin Paranoid OpenVPN changes"),
        *security_settings,
        Comment("# End Paranoid OpenVPN changes"),
        BlankLine(),
    ]

    for security_setting in security_settings:
        try:
            del config[security_setting.name]
        except KeyError:
            pass

    for i, setting in enumerate(lines_to_insert, start=config.last_before_inline()):
        config.insert(i, setting)

    if provider_ext == ProviderExtensions.PIA:
        process_pia(config)

    if cipher_strength == CipherStrength.WEAK:
        warnings.warn("Profile has WEAK cipher strength!")


def process_profiles(src: Path, dest: Path, min_tls: TLSVersion, provider_ext: ProviderExtensions) -> None:
    """Completely processes one or more OVPN profiles.

    :param src: Path to local input file or directory containing OVPN profile(s).
    :param dest: Path to the output file (if `src` was a file) or directory (if `src`) was a directory.
    :param min_tls: Minimum TLS version to require.
    :param provider_ext: Flag to indicate which, if any, provider specific tweaks to apply.
    """
    if src.is_file():
        dest.parent.mkdir(parents=True, exist_ok=True)
        config = OVPNConfig.read(src)
        process_profile(config, min_tls, provider_ext)
        config.write(dest)
    elif src.is_dir():
        # If dest is relative to src, rglob will cause this script to infinitely reprocess its own output
        if dest.is_relative_to(src):
            raise ValueError("dest path cannot be relative to src path")

        for child in src.rglob("*.*"):
            dest_file = dest / child.relative_to(src)
            dest_file.parent.mkdir(parents=True, exist_ok=True)

            if child.suffix == ".ovpn":
                config = OVPNConfig.read(child)
                process_profile(config, min_tls, provider_ext)
                config.write(dest_file)
            else:
                shutil.copy(child, dest_file)
    else:
        raise ValueError(f"Source does not exist: {src}")
