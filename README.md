# Paranoid OpenVPN

Paranoid OpenVPN hardens OpenVPN profiles and provides additional optional
provider-specific fixes (e.g. Priviate Internet Access).

## Usage

When installed, Paranoid OpenVPN provides the `paranoid_openvpn` executable
which comes with built-in help.  These are the common options:

```console
$ pip install paranoid-openvpn
$ # usage: paranoid_openvpn [--min-tls {1.0,1.1,1.2,1.3}] [--pia] source dest
$ # Process a remote zip file of OpenVPN profiles and apply PIA fixes
$ paranoid_openvpn --pia https://www.privateinternetaccess.com/openvpn/openvpn-strong.zip /path/to/output_dir
$ # Process one profile and allow TLS 1.2 (default is 1.3)
$ paranoid_openvpn --min-tls 1.2 /path/to/input/profile.ovpn /path/to/output/hardened.ovpn
```

`source` above can be a remote zip, remote single profile, local zip, local
single file, or local directory.

## Hardening OpenVPN

Most OpenVPN users are aware of the `cipher` and `hash` settings but that is
usually the extent of security options that people modify. OpenVPN, however,
has two distinct channels that each have their own security settings: the
control and data channel. The `cipher` and `hash` settings apply only to the
data channel but OpenVPN exposes settings for the control channel as well.
The control channel is used to exchange keys that are then used to encrypt
your traffic in the data channel.

Paranoid OpenVPN tries to match the security of the data channel to the control
channel. In broad terms, OpenVPN has options for <128-bit, 128-bit, 192-bit,
and 256-bit ciphers for the data channel. Paranoid OpenVPN will configure the
control channel to match these protection levels, with an absolute minimum of
128-bits.

## Cryptographic Reasoning

Where cryptographic judgement calls needed to be made, these rules were followed:

  * [AEAD ciphers](1) are always preferred over non-AEAD ciphers
  * At the 256-bit security level, AES-GCM was preferred over CHACHA20-POLY1305
    (for no particular reason).
  * The 192-bit security level is rounded up to 256-bit as there are no 192-bit
    TLS ciphers.
  * At the 128-bit security level, CHACHA20-POLY1305 was the preferred fallback
    for AES-128-GCM instead AES-128-CBC because it is an AEAD cipher.
    AES-128-CBC is then the fallback for CHACHA20-POLY1305.

[1]: https://en.wikipedia.org/wiki/Authenticated_encryption

## Provider-specific Fixes

Most VPN providers work fine with "normal" OpenVPN profiles but some providers
benefit from a few tweaks.

### Private Internet Access (PIA)

PIA's provided OpenVPN profiles seemingly only support AES-128-CBC and
AES-256-CBC as the `cipher` option.  However with a little coaxing, PIA will
connect using AES-256-GCM and AES-128-GCM. Using the `--pia` flag will allow
your client to client with these AEAD ciphers.

## Credit

A lot of inspiration for this project was taken from https://blog.securityevaluators.com/hardening-openvpn-in-2020-1672c3c4135a.