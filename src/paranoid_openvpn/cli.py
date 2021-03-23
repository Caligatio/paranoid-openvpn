import argparse
import logging
import sys
from pathlib import Path

from .input_handlers import ResolveSource
from .main import process_profiles
from .types import ProviderExtensions, TLSVersion

logger = logging.getLogger(__name__)


def cli() -> None:
    """Main command-line entry point into the program. Parses options and invokes the rest of the program."""
    parser = argparse.ArgumentParser(description="Harden OpenVPN profiles from popular providers")
    parser.add_argument("source", help="Path or HTTP to zip file containing original OpenVPN profiles")
    parser.add_argument("dest", type=Path, help="Path to output file or directory")
    parser.add_argument(
        "--min-tls", choices=["1.0", "1.1", "1.2", "1.3"], default="1.3", help="Minimum TLS version to require"
    )
    parser.add_argument(
        "--logging", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], help="Desired log level"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--pia", default=False, action="store_true", help="Add Private Internet Access fixes/hardening")

    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.logging), format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    if args.pia:
        provider_extensions = ProviderExtensions.PIA
    else:
        provider_extensions = ProviderExtensions.NONE

    try:
        with ResolveSource(args.source) as src:
            process_profiles(src, args.dest, TLSVersion(args.min_tls), provider_extensions)
            sys.exit(0)
    except Exception as exc:
        logging.critical("Failed processing source", exc_info=exc)
        sys.exit(1)
