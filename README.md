# fidokeyctl

`fidokeyctl` is a small OpenBSD-oriented utility for inspecting and managing FIDO security keys through `libfido2`.

The project aims to provide a simple, Unix-style command-line interface with a minimal dependency set and native OpenBSD hardening through `pledge(2)` and `unveil(2)`.

## Current status

Early development version.

Implemented:

- FIDO device discovery
- explicit device selection
- FIDO2 capability inspection
- PIN support/configuration status
- user verification capabilities
- credential management support
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
pin-set: no
uv-supported: no
uv-configured: no
credential-management: yes
versions: U2F_V2, FIDO_2_0, FIDO_2_1_PRE, FIDO_2_1
options: rk=yes, up=yes, plat=no, alwaysUv=no, credMgmt=yes, ...
aaguid: ff4dac45ede84ec2acedcf66103f4335
```

## Usage

```text
fidokeyctl [-d] -i [-f device]
```

Options:

- `-d` — enable `libfido2` debug output
- `-f device` — select a specific FIDO device
- `-i` — display authenticator information

If exactly one authenticator is connected, it is selected automatically.

## Build

On OpenBSD:

```sh
make
```

The project uses the native BSD make infrastructure and links against the system `libfido2`.

## Design goals

`fidokeyctl` follows a few deliberately conservative principles:

- small C codebase
- traditional Unix command-line interface
- OpenBSD coding conventions (man 9 style)
- predictable and script-friendly output
- no configuration files
- no unnecessary filesystem writes
- least-privilege execution with `pledge(2)` and `unveil(2)`
- direct use of `libfido2`

The project is currently developed and tested on OpenBSD.

## Roadmap

Future features will include:

- PIN creation and modification
- PIN retry information
- resident credential inspection and management
- additional CTAP2 diagnostics
- support for multiple authenticator management operations

## License

ISC License.
