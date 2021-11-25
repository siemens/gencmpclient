# generic CMP client

This is the Siemens-internal cross-division generic CMP client library
and associated CLI-based demo client, tests, and documentation.

**Note:** This [inner-source repository](https://code.siemens.com/product-pki/genCMPClient) is going to retire.
Please switch to the OSS repository at [https://github.com/siemens/gencmpclient](https://github.com/siemens/gencmpclient).


## Purpose

The purpose of this software is to provide a high-level API
on top of the detailed CMP (and CRMF) API of
[CMPforOpenSSL](https://github.com/mpeylo/cmpossl) and
and [OpenSSL](https://www.openssl.org/) since version 3.0.
The high-level API is on the one hand convenient to use for application
programmers and on the other hand complete and flexible enough
to cover the major certificate management use cases.
The library supports developing CMP clients that follow
the [Lightweight Certificate Management Protocol (CMP) Profile](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-lightweight-cmp-profile),
which is geared towards simple and interoperable industrial use.
The software also provides a command-line interface (CLI)
that is handy for interactive exploration of using CMP in a PKI.


## Status and changelog

* All features agreed with the participating Siemens business units
have been implemented and documented in FY 2019.
* Several hundreds of test cases have been compiled and executed successfully in FY 2020.
* [Open-source clearing has been finished](https://sw360.siemens.com/group/guest/projects/-/project/detail/a85b052efc1c3d42ebd3ef217fd600a4#/tab-ClearingStatus) in Feb 2020.
* Open-sourcing done on 17th September 2021 to [https://github.com/siemens/gencmpclient](https://github.com/siemens/gencmpclient).
* **This [inner-source repository](https://code.siemens.com/product-pki/genCMPClient) is going to retire.
Please switch to the [GitHub repository](https://github.com/siemens/gencmpclient).**
* Maintenance (i.e., minor updates and fixes, also to the documentation)
and feature extensions towards CMP version 3 are planned for FY 2022.

See the [CHANGELOG.md](CHANGELOG.md) file in the top-level directory.


## Documentation

The Generic CMP client API specification and CLI documentation are available in the [`doc`](doc/) folder.

The Doxygen documentation of the underlying Security Utilities library is available
via a link in its [README file](https://github.com/siemens/libsecutils/blob/master/README.md).

A recording of the tutorial held via Circuit on 2018-Dec-13 is available [here](https://myvideo.siemens.com/media/1_f7bjtdba).


## Prerequisites

This software should work with any flavor of Linux, including [Cygwin](https://www.cygwin.com/),
also on a virtual machine or the Windows Subsystem for Linux ([WSL](https://docs.microsoft.com/windows/wsl/about)).

The following network and development tools are needed or recommended.
* Git (for getting the software, tested with versions 2.7.2, 2.11.0, 2.20, 2.30.2)
* wget (for running the demo, tested with versions 1.17, 1.18, 1.20, 1.21)
* GNU make (tested with versions 4.1, 4.2.1, 4.3)
* GNU C compiler (gcc, tested with versions 5.4.0, 7.3.0, 8.3.0, 10.0.1, 10.2.1)

The following OSS components are used.
* OpenSSL development edition (tested with versions 1.0.2, 1.1.0, 1.1.1, 3.0)
* [Security Utilities (libsecutils)](https://github.com/siemens/libsecutils)
* [CMPforOpenSSL](https://github.com/mpeylo/cmpossl),
  a CMP+HTTP extension to OpenSSL, needed at least when using OpenSSL 1.x

For instance, on a Debian system these may be installed simply as follows:
```
sudo apt install libssl-dev
```
while `apt install wget git make gcc` usually is not needed as far as these tools are pre-installed.

Using the [CPP-VM](https://ccp.siemens.com/docs/meta-siemens/docs/getting-started/), all prerequisites are available out of the box.

As a sanity check you can execute in a shell:
```
git clone git@code.siemens.com:product-pki/genCMPClient.git
cd genCMPClient
make -f OpenSSL_version.mk
```
In order for this to work, you may need to set OPENSSL_DIR as described below,
e.g.,
```
export OPENSSL_DIR=/usr/local
```

This should output on the console something like
```
cc [...] OpenSSL_version.c -lcrypto -o OpenSSL_version
OpenSSL 1.1.1k  25 Mar 2021 (0x101010bf)
rm -f OpenSSL_version
```


## Getting the software

For accessing `git@code.siemens.com` you will need
an SSH client with credentials allowing to read from that repository.

For accessing the code repositories on GitHub from the Siemens intranet
you may need an SSH client with suitable credentials
or an HTTP proxy set up, for instance:
```
export https_proxy=http://de.coia.siemens.net:9400
```
<!---export no_proxy=$no_proxy,code.siemens.com  # not needed since we use SSH for the other (sub-)modules -->

You can clone the git repository and its submodules with
```
git clone git@code.siemens.com:product-pki/genCMPClient.git
cd genCMPClient
make get_submodules
```

This will fetch also the underlying [CMPforOpenSSL extension to OpenSSL](https://github.com/mpeylo/cmpossl) and
the [Security Utilities (libsecutils)](https://github.com/siemens/libsecutils) library.

For using the project as a git submodule,
do for instance the following in the directory where you want to integrate it:
```
git submodule add git@code.siemens.com:product-pki/genCMPClient.git
```

When you later want to update your local copy of all relevant repositories it is sufficient to invoke
```
make update
```


## Building the software

The generic CMP client (and also its underlying CMP and Security Utilities libraries)
assumes that OpenSSL (with any version >= 1.1.0) is already installed,
including the C header files needed for development
(as provided by, e.g., the Debian/Ubuntu package `libssl-dev`).
By default the OpenSSL headers will be searched for in `/usr/include`
and its shared objects in `/usr/lib` (or `/usr/bin` for Cygwin).
You may point the environment variable `OPENSSL_DIR` to an alternative OpenSSL installation, e.g.:
```
export OPENSSL_DIR=/usr/local
```
You may also specify using the environment variable `OUT_DIR`
where the produced libraries (`libgencmpcl`, `libcmp`, and `libsecutils´)
shall be placed. By default, the base directory (`.`) of `genCMPClient` is used.
For all path variables, relative paths such as `.` are interpreted
relative to the directory of the genCMPClient module.
For further details on optional environment variables,
see the [`Makefile`](Makefile) and [`Makefile_src`](Makefile_src).

In the newly created directory `genCMPClient` you can build the software simply with
```
make
```
where the CC environment variable may be set as needed; it defaults to %'gcc'.
Also the ROOTFS environment variable may be set, e.g., for cross compilation.

The result is in, for instance, `./libgencmpcl.so`.
This also builds all required dependencies (such as `./libsecutils.so` and `./libcmp.so`)
and an application (`./cmpClient`) for demonstration, test, and exploration purposes.

**Important Note:** by default, the Security Utilities supports using the
[Unified Trust Anchor (UTA) API](https://github.com/siemens/libuta) library
for secure device-level storage of key material for confidentiality and integrity protection of files.
Since the UTA library is not generally used, the SecUtils are by default integrated in a way that the use of the UTA lib is not enabled.
This means that unless the UTA library is enabled (via `SECUTILS_USE_UTA=1`) and used,
secure storage of protection credentials for private keys and trusted certificates needs to be solved by other means.


## Using the demo client

The CMP demo client is implemented in [`src/cmpClient.c`](src/cmpClient.c)
as part of the CLI.
It can be executed with
```
make demo_EJBCA
```

Among others, successful execution should produce a new certificate at `creds/operational.crt`.
You can view this certificate for instance by executing
```
openssl x509 -noout -text -in creds/operational.crt
```

The demo client may also interact with the external Insta Certifier Demo CA via
```
export SET_PROXY=http_proxy=de.coia.siemens.net:9400  # adapt to your needs
make demo_Insta
```


## Using the CLI-based client

The Command-Line Interface (CLI) of the CMP client is implemented in
[`src/cmpClient.c`](src/cmpClient.c).
It supports most of the features of the genCMPClient library.
The CLI use with the available options are documented in [`cmpClient-cli.pod`](doc/cmpClient-cli.pod).

CLI-based tests using the external Insta Demo CA may be invoked using
```
make test_Insta
```
where the PROXY environment variable may be used to override the default
(which is `http_proxy=de.coia.siemens.net:9400`)
in order to reach the Insta Demo CA.

```
make test_Simple
```
assuming a local SimpleLra instance is running and forwards requests
to the Siemens Product PKI (PPKI) Playground CA server.


## Using the library in own applications

For compiling applications using the library,
you will need to add the directories [`include`](include/) and
[`libsecutils/include`](https://github.com/siemens/libsecutils/blob/master/include/) to your C headers path.
Unless using OpenSSL 3.0, you need to
add also the directory [`cmpossl/include_cmp`](https://github.com/mpeylo/cmpossl/tree/cmp/include/),
define the C macro `CMP_STANDALONE`, and
make sure that any OpenSSL header files included have the same version
as the one used to build the standalone CMP library `libcmp`.

For linking you will need to
refer the linker to the CMP and Security Utilities libraries,
e.g., `-lsecutils -lcmp -lgencmpcl`.
Unless using OpenSSL 3.0, `-lcmp` is needed as well.
Add the directories (e.g., with the linker option `-L`) where they can be found.
See also the environment variable `OUT_DIR`.
For helping the Linux loader to find the libraries at run time,
it is recommended to set also linker options like `-Wl,-rpath=.`.

Also make sure that the OpenSSL libraries (typically referred to via `-lssl -lcrypto`) are in your library path and
(the version) of the libraries found there by the linker match the header files found by the compiler.

For building your application you will need to `#include` the header file [`genericCMPClient.h`](include/genericCMPClient.h) and link using `-lgencmpcl`.

All this is already done for the cmp client application.


## Disclaimer

This software including associated documentation is provided ‘as is’.
Effort has been spent on quality assurance, but there are no guarantees.


## License

This work is licensed under the terms of the Apache Software License 2.0.
See the [LICENSE.txt](LICENSE.txt) file in the top-level directory.

SPDX-License-Identifier: Apache-2.0
