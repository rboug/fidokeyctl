# fidokeyctl

`fidokeyctl` is a small OpenBSD-oriented utility for inspecting and managing FIDO security keys through `libfido2`.

The project aims to provide a simple, Unix-style command-line interface with a minimal dependency set and native OpenBSD hardening through `pledge(2)` and `unveil(2)`.

## Current status

Early development version.

Implemented:

- FIDO device discovery
- explicit device selection
- FIDO2 capability inspection
- PIN support and configuration status
- PIN creation
- PIN modification
- PIN retry counter
- user verification capabilities
- credential management capability detection
- CTAP2 versions and options
- AAGUID display
- optional `libfido2` debug output
- `pledge(2)` / `unveil(2)` sandboxing

Example:

```sh
$ fidokeyctl -i
device: /dev/fido/0
protocol: FIDO2
pin-supported: yes
pin-set: yes
uv-supported: no
uv-configured: no
credential-management: yes
versions: U2F_V2, FIDO_2_0, FIDO_2_1_PRE, FIDO_2_1
options: rk=yes, up=yes, plat=no, alwaysUv=no, credMgmt=yes, authnrCfg=yes, clientPin=yes, largeBlobs=yes, pinUvAuthToken=yes, setMinPINLength=yes, makeCredUvNotRqd=yes, credentialMgmtPreview=yes
aaguid: ff4dac45-ede8-4ec2-aced-cf66103f4335
```

PIN retry information can be queried independently:

```sh
$ fidokeyctl -r
pin-retries: 8
```

## Usage

```text
fidokeyctl [-diPpr] [-f device]
```

Options:

- `-d` — enable `libfido2` debug output
- `-f device` — select a specific FIDO device
- `-i` — display authenticator information
- `-p` — set the initial FIDO2 PIN
- `-P` — change an existing FIDO2 PIN
- `-r` — display the remaining PIN retry count

If exactly one authenticator is connected, it is selected automatically.

Multiple read-only operations may be combined, for example:

```sh
fidokeyctl -ir
```

PINs are read directly from the terminal without echo and are never accepted as command-line arguments.

Debug mode cannot be combined with PIN operations in order to avoid exposing sensitive data through diagnostic output.

## Build

On OpenBSD:

```sh
make
```

To install the program and manual page:

```sh
doas make install
```

The project uses the native BSD make infrastructure and links directly against the system `libfido2`.

## Design goals

`fidokeyctl` follows a deliberately conservative set of principles:

- small C codebase
- traditional Unix command-line interface
- OpenBSD coding conventions (`style(9)`)
- predictable and script-friendly output
- no configuration files
- no unnecessary filesystem writes
- no secrets passed through command-line arguments
- sensitive buffers explicitly cleared after use
- least-privilege execution with `pledge(2)` and `unveil(2)`
- direct use of `libfido2`
- vendor-independent FIDO2 support where possible

The project is currently developed and tested on OpenBSD.

## Scope

`fidokeyctl` focuses on FIDO2 and CTAP2 functionality exposed through `libfido2`.

It is not intended to replace vendor-specific tools for unrelated functionality such as OTP, PIV, OpenPGP, or other proprietary security-key applications.

## Roadmap

Future features include:

- resident/discoverable credential inspection and management
- additional CTAP2 capability and configuration information
- improved PIN error and lockout reporting
- CTAP2 configuration operations
- support for additional authenticator management operations
- carefully guarded destructive operations such as FIDO reset
- machine-readable output

## License

ISC License.
