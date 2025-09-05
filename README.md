# generic CMP client

This is a generic Certificate Management Protocol (CMP) client library with

* a high-level API for use with C(++)
* an associated CLI-based demo client
* CLI-based demo invocations and tests
* documentation for the API and CLI

## Purpose

The purpose of this software is to provide the latest CMP features
and an easy-to-use high-level C-based CMP API
on top of the [OpenSSL library](https://www.openssl-library.org/).

The library supports developing CMP clients that adhere to
the [Lightweight CMP Profile (LCMPP)](https://www.rfc-editor.org/rfc/rfc9483),
which is geared towards simple and interoperable industrial use.

The [high-level API](doc/Generic_CMP_client_API.pdf)
is convenient to use for application programmers
while being sufficiently complete and flexible
to cover all major certificate management use cases.

The software also provides a [command-line interface](doc/cmpClient.pod) (CLI),
which is handy for demonstrating and interactively exploring the use of CMP
with a given CMP server, which may be part of a PKI.\
Yet for productive use, interfacing at API level is more direct and secure.

The underlying OpenSSL library implements CMP, CRMF, HTTP, etc.
with a detailed low-level API, which is rather difficult to use.
Its version 3.0 covers CMPv2 and HTTP(s) transfer as originally defined in
[RFC 4210](https://www.rfc-editor.org/rfc/rfc4210) and
[RFC 6712](https://www.rfc-editor.org/rfc/rfc6712),
which is sufficient for most scenarios.
Later OpenSSL versions cover also more recent and special CMP features
added by [RFC 9480](https://www.rfc-editor.org/rfc/rfc9480),
which meanwhile has been obsoleted by
[RFC 9810](https://www.rfc-editor.org/rfc/rfc9810) and
[RFC 9811](https://www.rfc-editor.org/rfc/rfc9811).
For details see [below](#cmp-features-and-openssl-versions)
or the HISTORY section of [`cmpClient.pod`](doc/cmpClient.pod#HISTORY).

A further use case of this software is to provide early access to all new CMP
features defined in [CMP Updates](https://www.rfc-editor.org/rfc/rfc9480) and
the [Lightweight CMP Profile (LCMPP)](https://www.rfc-editor.org/rfc/rfc9483).
To this end, the software can use in addition the intermediate CMP library
[CMPforOpenSSL](https://github.com/mpeylo/cmpossl), called `libcmp` below.
This is needed only as long as special new CMP(v3) features are required
that are not covered by the OpenSSL version being used.

Note: An OSS CMP client and registration authority (RA) implementation in Java
is available in the form of a
[generic CMP RA and client component](https://github.com/siemens/cmp-ra-component).
The [LightweightCmpRa](https://github.com/siemens/LightweightCmpRa)
is a CLI-based demo CMP client and RA application making use of this component.

## Support model

The [maintainers](MAINTAINERS) offer two levels of support.

* Community support is provided on a best-effort basis
  and can be requested via [issues](../../issues).
* Paid professional support and consulting can be ordered
  from Siemens by reaching out to the maintainers.

[Contributions](CONTRIBUTING.md) are appreciated
  in the form of [pull requests](../../pulls).

## Status

This software provides all features of CMP version 3
as defined in [CMP Updates](https://www.rfc-editor.org/rfc/rfc9480) according
to the [Lightweight CMP Profile (LCMPP)](https://www.rfc-editor.org/rfc/rfc9483),
which has been defined for simple and interoperable industrial use of CMP.

<!--
As of November 2024, upstream contribution of the new CMP version 3 features
to OpenSSL is nearly finished. OpenSSL version 3.4 contains all of them except
for [central key generation](https://github.com/openssl/openssl/pull/25132).
-->

Note that in 2025,
[RFC 9810](https://www.rfc-editor.org/rfc/rfc9810) and
[RFC 9811](https://www.rfc-editor.org/rfc/rfc9811)
obsoleted RFCs 4210, 6712, and 9480 (CMP Updates).
As of July 2025,
support for enrolling and using KEM certificates,
which is main novelty of RFC 9810, is not avialable here.

<!--
The [CHANGELOG.md](CHANGELOG.md) contains a coarse release history.
-->

## Documentation

The Generic CMP client API specification and CLI documentation
are available in the [`doc`](doc/) folder.

The Doxygen documentation of the underlying Security Utilities library is available
via a link in its [README file](https://github.com/siemens/libsecutils/blob/master/README.md).

## Prerequisites

This software should work with any flavor of Linux
including Debian, macOS and [Cygwin](https://www.cygwin.com/),
on a native system, a Docker image, or on a virtual machine including the
Windows Subsystem for Linux ([WSL](https://docs.microsoft.com/windows/wsl/about)).

The following development and network tools are needed or recommended.

* Git (for getting the software, tested versions include 2.7.2, 2.11.0, 2.20, 2.30.2, 2.39.2, 2.47.0)
* CMake (for using [`CMakeLists.txt`](CMakeLists.txt), tested versions include 3.18.4, 3.26.3, 3.27.7, 3.30.5)
* GNU make (tested versions include 3.81, 4.1, 4.2.1, 4.3)
* GNU C compiler (gcc, tested versions include 5.4.0, 7.3.0, 8.3.0, 10.0.1, 10.2.1, 12.2.0)
  or clang (tested versions include 14.0.3, 17.0.3, 19.1.1)
* wget (for running the demo, tested versions include 1.17, 1.18, 1.20, 1.21.3, 1.24.5)
* Perl (for running the tests, tested versions include 5.30.3, 5.32.1, 5.36.0, 5.38.2)

The following OSS components are used.

* OpenSSL development edition;
  currently supported versions include 3.0, 3.1, 3.2, 3.3, 3.4
  <!-- (formerly also versions 1.0.2, 1.1.0, and 1.1.1) -->
* [Security Utilities (libsecutils)](https://github.com/siemens/libsecutils)
  for support (not core) functionality needed mostly for the CLI
* [CMPforOpenSSL](https://github.com/mpeylo/cmpossl),
  an intermediate CMP+CRMF+HTTP extension to OpenSSL,
  needed only if the OpenSSL version being used does not yet include
  all CMP features required for the given CMP application scenario,
  which can be indicated by setting the environment variable `USE_LIBCMP`.

For an overview of CMP features relevant in industrial use cases see
[LCMPP section 7.1](https://datatracker.ietf.org/doc/html/rfc9483#section-7.1).

## CMP features and OpenSSL versions

CMP client (EE) features are supported by the genCMPClient as follows.

The features defined with CMPv3
in [RFC 9480 (CMP Updates)](https://www.rfc-editor.org/rfc/rfc9480)
are fully covered when using the [intermediate CMP library `libcmp`](
https://github.com/mpeylo/cmpossl) or when using at least OpenSSL 3.5.

Since the intermediate CMP library `libcmp` constitutes an extra dependency
and its maintenance is going to end soon rather after the release of OpenSSL 3.5,
better avoid using it. This is possible if all the CMP features needed
by the application scenario are covered by the OpenSSL version being used.

* OpenSSL 3.0 sufficiently covers the CMPv2 features defined in
[RFC 4210](https://www.rfc-editor.org/rfc/rfc4210).\
  This includes most of the
  "Generic Aspects of PKI Messages and PKI Management Operations",
  IR, CR, KUR, P10CR, MAC, RR, and polling for certification responses.
* In OpenSSL 3.2, "Get CA Certificates" and "Get Root CA Certificate Update"
  were added.
* In OpenSSL 3.3, "Get Certificate Request Template" and support for certificate
  profiles and generalized polling ("Handling Delayed Delivery") were added.
* In OpenSSL 3.4, "CRL Update Retrieval" was added.
* In OpenSSL 3.5, support for central key generation is going to be added.

Hint: As long as your system provides a sufficiently recent version of OpenSSL
and related development header files,
better not manually install in addition a different OpenSSL version unless
you need newer CMP features without using the intermediate CMP library `libcmp`.
Such an extra installation can interfere with the more or less implicit references
to the default locations of OpenSSL header files and binary library files.
So unless knowing exactly what to do and being careful, one may receive version
mismatch errors like the one mentioned [below](#sanity-checks-on-openssl).
<!-- https://github.com/orgs/community/discussions/60861-->

### Linux installation

On a Debian or Ubuntu system the prerequisites may be installed simply as follows:

```bash
sudo apt install cmake libssl-dev libc-dev linux-libc-dev
```

while `sudo apt install git make gcc wget`
usually is not needed as far as these tools are pre-installed.

### macOS installation

On macOS the prerequisites may be installed
by executing the following in a terminal:

```bash
brew install git make openssl cmake wget perl
```

For making sure that OpenSSL version 3 is installed:

```bash
brew uninstall --ignore-dependencies openssl@3
brew install openssl@3
brew --prefix openssl@3
```

For using `gcc` (instead of `clang`) and `ccache`:

```bash
brew install gcc ccache
```

### Sanity checks on OpenSSL

As a sanity check whether OpenSSL is usable for building the CMP client and libraries,
you can execute in a shell on a Unix-like system:

```bash
git clone https://github.com/siemens/gencmpclient.git
cd genCMPClient
make -f OpenSSL_version.mk
```

This should give various diagnostic output,
on success ending with a line giving the detected OpenSSL version like

```bash
...
cc [...] OpenSSL_version.c -lcrypto -o OpenSSL_version
...
OpenSSL 3.0.13 30 Jan 2024 (0x300000d0)
```

You may need to set the variable `OPENSSL_DIR` first as described [below](#configuring), e.g.,

```bash
export OPENSSL_DIR=/usr/local
```

When having trouble building, which may be due to unsuitably set environment variables,
this can provide useful information.

When getting version mismatch errors like

```bash
OpenSSL runtime version 0x30400000 does not match version 0x300000d0 used by compiler
```

make sure that the system-level configuration for finding header and library files
as well as the optional environment variables `OPENSSL_DIR` and `OPENSSL_LIB`
described [below](#configuring) are set up in a consistent way.

## Getting the software

For accessing the code repositories on GitHub
you may need an SSH client with suitable credentials
or an HTTP proxy set up, for instance:

```bash
export https_proxy=http://proxy.example.com:8080
```

You can clone the git repository and its submodules with

```bash
git clone https://github.com/siemens/gencmpclient.git
cd genCMPClient
make -f Makefile_v1 get_submodules
```

This will fetch also the underlying
[CMPforOpenSSL extension to OpenSSL](https://github.com/mpeylo/cmpossl) if needed and
the [Security Utilities (libsecutils)](https://github.com/siemens/libsecutils) library.

For using the project as a git submodule,
do for instance the following in the directory where you want to integrate it:

```bash
git submodule add git@github.com:siemens/gencmpclient.git
```

When you later want to update your local copy of all relevant repositories
it is sufficient to invoke

```bash
make update
```

When switching to a certain commit or version, e.g.

```bash
git checkout v2.0
```

then also execute

```bash
git submodule update
make -f Makefile_v1 clean
```

to bring the submodules in a state consistent with that
and remove any previous possibly outdated artifacts.

## Configuring

### Finding OpenSSL

The generic CMP client, as well as its underlying libraries,
assumes that OpenSSL is already installed,
including the C header files needed for development.

By default, any OpenSSL installation that is
found at the usual locations on the system is used.
This typically works automatically (using some heuristics)
when, e.g., the Debian/Ubuntu package `libssl-dev`
or the macOS brew package `openssl@3` has been installed.

Otherwise it may be needed to manually set
the environment variable `OPENSSL_DIR` to specify
the path of the OpenSSL installation (or local build directory) to use.
This must point to the location in the file system
from which the subdirectory `include/openssl`
is directly accessible with this relative path name.\
When used with CMake, `$OPENSSL_DIR/OpenSSLConfig.cmake` must exist.

In case the OpenSSL libraries are in an unusual location,
it may be necessary to set also `OPENSSL_LIB`.
Otherwise some heuristics will try to detect it,
which may go wrong in particular if multiple OpenSSL versions are available.

For all environment variables specifying a directory,
absolute or relative paths (including `.`) may be used.
Relative paths are interpreted relative to the genCMPClient source directory.

#### Linux

Here are examples of typical OpenSSL directory locations for Linux:

```bash
export OPENSSL_DIR=/usr
export OPENSSL_LIB=/lib/x86_64-linux-gnu
```

The value for `OPENSSL_LIB` may be obtained by

```bash
ldd `which openssl` | grep libcrypto.so | awk '{print $3}' | sed 's#/[^/]*$##'
```

Yet for the most common cases it is not needed to set these
environment variables manually.

#### macOS

When OpenSSL has been installed on macOS using `brew`,
it is typically not needed to set specific environment variables.\
Nevertheless, they may be defined for instance in ``~/.zshrc`` like this:

```bash
export LDFLAGS="-L$(brew --prefix openssl@3)/lib"
export CPPFLAGS="-I$(brew --prefix openssl@3)/include"
export OPENSSL_DIR=$(brew --prefix openssl@3)
export OPENSSL_LIB=$(brew --prefix openssl@3)/lib
```

After doing so, restart the terminal or copy&paste these line there, too.

### Using of `libcmp` and `libsecutils`

Only if needed,
define the environment variable `USE_LIBCMP` for using the latest CMP features
and fixes, which implies use of the intermediate library `libcmp`.
When using CMake, do this both when calling `cmake` (at generation time)
and when calling `make` (e.g., at build time).
<!-- When using OpenSSL version 1.x, this is ensured automatically. -->
When using OpenSSL versions before 3.5 and `USE_LIBCMP` is not defined,
not all of the CMP features newly defined in CMP Updates
and in the Lightweight CMP Profile (LCMPP) are supported,
which usually is not a problem.

From use with the underlying Security Utilities library
the following environment variables may be set
when calling `cmake` (at generation time) or when using `Makefile_v1`.

* If `SECUTILS_USE_ICV` is set, configuration files are expected
to be integrity protected with an Integrity Check Value (ICV),
which may be produced using `util/icvutil`.
* Use of the UTA library can be enabled by setting `SECUTILS_USE_UTA`.
  The UTA library must have been pre-installed on the system.
* The TLS-related functions may be disabled by setting `SECUTILS_NO_TLS`,
  which also needs to be done when calling `make` at build time.

### Using CMake or `Makefile_v1`

Since genCMPClient version 2, it is recommended to use CMake
to produce the `Makefile`, for instance as follows:

```bash
cmake .
```

After modifying (i.e., setting or unsetting) relevant environment variables,
it is recommended to remove `CMakeCache.txt` and re-run CMake.

By default, CMake builds are in Release mode.
This may also be enforced by defining the environment variable `NDEBUG`.
For switching to Debug mode, use `cmake` with `-DCMAKE_BUILD_TYPE=Debug`.
The chosen mode is remembered in `CMakeCache.txt`.

For backward compatibility it is also possible to use instead of CMake
pre-defined [`Makefile_v1`](Makefile_v1); to this end symlink it to `Makefile`:

```bash
ln -s Makefile_v1 Makefile
```

or use for instance `make -f Makefile_v1`.

By default, builds using `Makefile_v1` are in Debug mode.
Release mode can be selected by defining the environment variable `NDEBUG`.

By default `Makefile_v1` behaves as if

```bash
OPENSSL_DIR=/usr
```

was given, such that the OpenSSL headers will be searched for in `/usr/include`
and its shared objects in `/usr/lib` (or `/usr/bin` for Cygwin).

When using [`Makefile_v1`](Makefile_v1), you may
specify via the environment variable `OUT_DIR` where the produced libraries
(e.g., `libgencmp.so*`, `libcmp.so*`, and `libsecutils.so*`) shall be placed.
It defaults to the base directory of the respective library.
If the environment variable `BIN_DIR` is not empty, the
the CLI application `cmpClient` will be built and placed in `BIN_DIR`.
If the variable is unset, `.` is used by default.
The CC environment variable may be set as needed; it defaults to `gcc`.
It is also possible to statically link with `libcmp.a`, by setting `STATIC_LIBCMP=1`.
For further details on optional environment variables,
see the [`Makefile_v1`](Makefile_v1) and [`Makefile_src`](Makefile_src).

## Building

Build the software with

```bash
make
```

(or `make -f Makefile_v1`).

The result is in, for instance, `libgencmp.so.2.0`.
This also builds all required dependencies
(such as `libsecutils.so.2.0` and possibly `libcmp.so.2.0`)
and a CLI application (`./cmpClient`), which is intended
for demonstration, test, and exploration purposes.

When getting the compiler error: `'openssl/openssl_backport.h' file not found`
likely `include/genericCMPClient_config.h` is outdated
and contains `#define USE_LIBCMP` although the environment variable `USE_LIBCMP`
is not set.
In such situations, `make clean`  (or `make -f Makefile_v1 clean`) helps to reset it to a consistent state.

### Installing and uninstalling

The software can be installed with, e.g.,

```bash
sudo make install
```

and uninstalled with

```bash
sudo make uninstall
```

The destination base directory is `/usr/local/`,\
unless specified otherwise using `DESTDIR` or `ROOTFS`.
With that directory, artifacts are placed in the usual subdirectories:

* libraries below `lib/` with CMake file in the subdirectory `cmake/`
* other binaries in `bin/`
* documentation below `share/doc`
* man pages below `share/man`
* header files below `include/`

### Cleaning up

`make clean` removes part of the artifacts, while\
`make clean_all` removes everything produced by `make` and `CMake`.

## Building Debian packages (for use also with Ubuntu etc.)

This repository can build the following binary and source packages.

* `libgencmp` - the shared library
* `libgencmp-dev` - development headers and documentation
* `cmpclient` - simple command-line application with its documentation
* `libgencmp*Source.tar.gz` -- source tarball

The recommended way is to use CPack with the files produced by CMake as follows:

```bash
make deb
```

which requires the `file` utility.

Alternatively, [`Makefile_v1`](Makefile_v1) may be used like this:

```bash
make -f Makefile_v1 deb
```

In this case, the resulting packages are placed in the parent directory (`../`)\
and the following Debian packages are required:

* `debhelper` (needed for `dh`)
* `devscripts` (needed for `debuild`)
* `libssl-dev`
<!--
* `libsecutils-dev`
* `libcmp-dev` (if used)
--->

The Debian packages may be installed for instance as follows:

```bash
sudo dpkg -i libgencmp*deb cmpclient_*.deb
```

## Using the CLI-based demo client

The Command-Line Interface (CLI) of the CMP client is implemented in
[`src/cmpClient.c`](src/cmpClient.c).
It supports most of the features of the genCMPClient library.
The CLI use with the available options are documented in [`cmpClient.pod`](doc/cmpClient.pod).
An example configuration used by the below mentioned demo invocations
can be found in [`demo.cnf`](config/demo.cnf).

For simple test invocations the Insta Certifier Demo CA server may be used,
for instance as follows:

```bash
openssl ecparam -genkey -name prime256v1 -out test.key.pem
./cmpClient -config "" -server pki.certificate.fi:8700/pkix/ \
  -recipient "/C=FI/O=Insta Demo/CN=Insta Demo CA" \
  -secret pass:insta -ref 3078 \
  -cmd cr -newkey test.key.pem -subject "/CN=test" -certout test.cert.pem
openssl x509 -noout -text -in test.cert.pem
```

As the CMP client interacts via HTTP with an external CMP server, depending
on your network you may need to set the environment variable `http_proxy`.

A demo making use of all supported CMP commands can be executed with

```bash
make -f Makefile_v1 demo
```

The demo can be run using the online Insta Demo CA, which is the default,
or using an included Docker instance of the EJBCA that can be launched locally:

```bash
make -f Makefile_v1 demo_EJBCA
```

or using the reference playground CA operated by Siemens over a test cloud CA:

```bash
make -f Makefile_v1 demo_CloudCA
```

Among others, successful execution should produce a new certificate at `creds/operational.crt`.
You can view this certificate for instance by executing

```bash
openssl x509 -noout -text -in creds/operational.crt
```

To select a specific CMP profile on the CloudCA server, set the environment
variable `CMP_PROFILE` to the profile name.
For instance use either

```bash
CMP_PROFILE=PPKI%20Playground%20ECC make -f Makefile_v1 demo_CloudCA
```

or

```bash
CMP_PROFILE=PPKI%20Playground%20RSA make -f Makefile_v1 demo_CloudCA
```

to switch between an ECC-based CA hierarchy (which is the default) or an RSA-based CA hierarchy.

CLI-based tests using the Insta Demo CA may be invoked using

```bash
make -f Makefile_v1 test_Insta
```

where the PROXY environment variable may be used to override the default
in order to reach the Insta Demo CA.

In order to obtain a trace of the HTTP messages being sent and received,
one can build the genCMPClient with `USE_LIBCMP=1` and
set the environment variable `OPENSSL_TRACE` to contain the string `"HTTP"`.
For instance:

```bash
OPENSSL_TRACE=HTTP ./cmpClient imprint -section Insta
```

## Using the library in own applications

For building the library (and optionally the CLI application)
as part of other builds, it is recommended to use Debian packages or CMake.

Another possibility is to use [`Makefile_v1`](Makefile_v1),
for instance as given in the example outer [`Makefile.mk`](Makefile.mk).

For compiling applications using the library,
you will need to `#include` the header file [`genericCMPClient.h`](include/genericCMPClient.h)
and add the directories [`include`](include/) and
[`libsecutils/include`](
https://github.com/siemens/libsecutils/blob/master/include/) to your C headers path.
When the intermediate library `libcmp` is used, you need to
add also the directory [`cmpossl/include/cmp`](
https://github.com/mpeylo/cmpossl/tree/cmp/include/cmp/),
define the C macro `USE_LIBCMP`, and
make sure that any OpenSSL header files included have the same version
as the one used to build `libcmp`.

For linking you will need to
refer the linker to the CMP and Security Utilities libraries,
e.g., `-lsecutils -lgencmp`.
When `libcmp` is used, `-lcmp` is needed additionally.
Add the directories (e.g., with the linker option `-L`) where they can be found.
See also the environment variable `OUT_DIR`.
Consider using also linker options like `-Wl,-rpath,.`
for helping the Linux loader find the libraries at run time.

Also make sure that the OpenSSL libraries
(typically referred to via `-lssl -lcrypto`) are in your library path and
(the version of) the libraries found there by the linker
match the header files found by the compiler.

All this is already done for the CMP client application `cmpClient`.

## Disclaimer

This software including associated documentation is provided ‘as is’.
Effort has been spent on quality assurance, but there are no guarantees.

## License

This work is licensed under the terms of the Apache Software License 2.0.
See the [LICENSE.txt](LICENSE.txt) file in the top-level directory.

SPDX-License-Identifier: Apache-2.0

<!--
LocalWords:  genericCMPClient CHANGELOG doc libcmp openssl sudo cmake libssl cd
LocalWords:  dev libc linux DIR perl ccache mk LIB ldd grep awk lcrypto KUR RR
LocalWords:  libcrypto sed zshrc LDFLAGS lib CPPFLAGS SECUTILS lsecutils CMPv
LocalWords:  util icvutil NDEBUG DCMAKE ln usr libgencmp CC lssl lcmp md bis
LocalWords:  cmpClient src DESTDIR ROOTFS cmpclient tarball deb rpath
LocalWords:  debhelper dh devscripts debuild dpkg ecparam FI cr lgencmp cc cnf
LocalWords:  genkey insta ref cmd newkey certout noout creds Wl ICV
-->
