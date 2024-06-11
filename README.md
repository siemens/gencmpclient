# generic CMP client

This is a generic Certificate Management Protocol (CMP) client library
with a high-level API
and associated CLI-based demo client, tests, and documentation.

## Purpose

The purpose of this software is to provide a high-level API
on top of the detailed CMP (and CRMF) API of
[OpenSSL](https://www.openssl.org/) since version 3.0.
It can be used with OpenSSL and with the intermediate CMP library
[CMPforOpenSSL](https://github.com/mpeylo/cmpossl)
providing the latest CMP features defined in [CMP Updates
](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cmp-updates).

The high-level API is on the one hand convenient to use for application
programmers and on the other hand complete and flexible enough
to cover the major certificate management use cases.
The library supports developing CMP clients that adhere to
the [Lightweight CMP Profile (LCMPP)
](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-lightweight-cmp-profile),
which is geared towards simple and interoperable industrial use.
The software also provides a command-line interface (CLI)
that is handy for interactive exploration of using CMP in a PKI.


## Status and changelog

See the [CHANGELOG.md](CHANGELOG.md) file in the top-level directory.


## Documentation

The Generic CMP client API specification and CLI documentation are available in the [`doc`](doc/) folder.

The Doxygen documentation of the underlying Security Utilities library is available
via a link in its [README file](https://github.com/siemens/libsecutils/blob/master/README.md).


## Prerequisites

This software should work with any flavor of Linux, including [Cygwin](https://www.cygwin.com/),
also on a virtual machine or the Windows Subsystem for Linux ([WSL](https://docs.microsoft.com/windows/wsl/about)),
and with MacOS.

The following network and development tools are needed or recommended.
* Git (for getting the software, tested with versions 2.7.2, 2.11.0, 2.20, 2.30.2, 2.39.2)
* CMake (for using [`CMakeLists.txt`](CMakeLists.txt), tested with versions 3.18.4, 3.26.3, 3.27.7)
* GNU make (tested with versions 3.81, 4.1, 4.2.1, 4.3)
* GNU C compiler (gcc, tested with versions 5.4.0, 7.3.0, 8.3.0, 10.0.1, 10.2.1)
  or clang (tested with version 14.0.3 and 17.0.3)
* wget (for running the demo, tested with versions 1.17, 1.18, 1.20, 1.21)
* Perl (for running the tests, tested with versions 5.30.3 and 5.32.1)

The following OSS components are used.
* OpenSSL development edition; supported versions: 3.0, 3.1, 3.2
  <!-- (formerly also versions 1.0.2, 1.1.0, and 1.1.1) -->
* [Security Utilities (libsecutils)](https://github.com/siemens/libsecutils)
* [CMPforOpenSSL](https://github.com/mpeylo/cmpossl),
  a CMP+CRMF+HTTP extension to OpenSSL, needed when using OpenSSL 1.x
  or if the latest CMP features not yet available in OpenSSL are required,
  which can be indicated by setting the environment variable `USE_LIBCMP`.

### Linux installation

For instance, on a Debian or Ubuntu system the prerequisites may be installed simply as follows:
```
sudo apt install cmake libssl-dev libc-dev linux-libc-dev
```
while `sudo apt install git make gcc wget` usually is not needed as far as these tools are pre-installed.

You might need to set the variable `OPENSSL_DIR` first as described below, e.g.,
```
export OPENSSL_DIR=/usr/local
```

### OS X installation

On a Mac OS X system the following steps need to be executed in a terminal:

```
brew install git
brew install CMake
brew install make
brew install gcc
brew install wget
brew install perl    
brew uninstall --ignore-dependencies openssl@3
brew install openssl@3
brew --prefix openssl@3
```

These lines need to be added to ``~/.zshrc``

```
export LDFLAGS="-L$(brew --prefix openssl@3)/lib"
export CPPFLAGS="-I$(brew --prefix openssl@3)/include"
export OPENSSL_DIR=$(brew --prefix openssl@3)
export OPENSSL_LIB=$(brew --prefix openssl@3)/lib
```

After adding these lines, the terminal needs to be restarted.

### Common steps

As a sanity check you can execute in a shell on a Unix-like system:
```
git clone https://github.com/siemens/gencmpclient.git
cd genCMPClient
make -f OpenSSL_version.mk

```

This should output on the console something like
```
cc [...] OpenSSL_version.c -lcrypto -o OpenSSL_version
OpenSSL 3.0.8 7 Feb 2023 (0x30000080)
```

## Getting the software

For accessing the code repositories on GitHub
you may need an SSH client with suitable credentials
or an HTTP proxy set up, for instance:
```
export https_proxy=http://proxy.example.com:8080
```

You can clone the git repository and its submodules with
```
git clone https://github.com/siemens/gencmpclient.git
cd genCMPClient
make -f Makefile_v1 get_submodules  
```

This will fetch also the underlying [CMPforOpenSSL extension to OpenSSL](https://github.com/mpeylo/cmpossl) if needed and
the [Security Utilities (libsecutils)](https://github.com/siemens/libsecutils) library.

For using the project as a git submodule,
do for instance the following in the directory where you want to integrate it:
```
git submodule add git@github.com:siemens/gencmpclient.git
```

When you later want to update your local copy of all relevant repositories
it is sufficient to invoke
```
make update
```


## Configuring

The generic CMP client (as well as its underlying libraries)
assumes that OpenSSL is already installed,
including the C header files needed for development
(as provided by, e.g., the Debian/Ubuntu package `libssl-dev`).

By default any OpenSSL installation available on the system is used.

> [!TIP]
>
> **Only on Linux**
>
> Set the optional environment variable `OPENSSL_DIR` to specify the
> absolute (or relative to `../`) path of the OpenSSL installation to use, e.g.:
>```
>export OPENSSL_DIR=/usr/local
>```
>This must point to the location in the file system from which `include/openssl`
>is directly accessible with this relative path name.\
>In case its libraries are in a different location, set also `OPENSSL_LIB`, e.g.:
>```
>export OPENSSL_LIB=/lib/x86_64-linux-gnu
>```
>The needed value may be obtained by
>```
>ldd `which openssl` | grep libcrypto.so | awk '{print $3}' | sed 's#/[^/]*$##'
>```

Define the environment variable `USE_LIBCMP` for using the latest CMP features
and fixes, which implies use of the intermediate library `libcmp`.
When using OpenSSL version 1.x, this is ensured automatically.
When using OpenSSL version 3.0 or 3.1 and `USE_LIBCMP` is not defined,
the new CMP features defined in CMP Updates and the Lightweight CMP Profile
will not be supported.

From the underlying Security Utilities library
the following environment variables are inherited.
* When `SECUTILS_USE_ICV` is set, configuration files are expected
to be integrity protected with an Integrity Check Value (ICV),
which may be produced using `util/icvutil`.
* Use of the UTA library can be enabled by setting `SECUTILS_USE_UTA`.
* The TLS-related functions may be disabled by setting `SECUTILS_NO_TLS`.

Since genCMPClient version 2, it is recommended to use CMake
to produce the `Makefile`, for instance as follows:
```
cmake .
```
When using CMake, `cmake` must be (re-)run
after setting or unsetting environment variables.
By default, CMake builds are in Release mode.
This may also be enforced by defining the environment variable `NDEBUG`.
For switching to Debug mode, use `cmake` with `-DCMAKE_BUILD_TYPE=Debug`.
The chosen mode is remembered in `CMakeCache.txt`.

For backward compatibility it is also possible to use instead of CMake
pre-defined [`Makefile_v1`](Makefile_v1); to this end symlink it to `Makefile`:
```
ln -s Makefile_v1 Makefile
```
or use for instance `make -f Makefile_v1`.

By default, builds using `Makefile_v1` are in Debug mode.
Release mode can be selected by defining the environment variable `NDEBUG`.

By default `Makefile_v1` behaves as if
```
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
For all path variables, relative paths such as `.` are interpreted
relative to the directory of the genCMPClient module.
The CC environment variable may be set as needed; it defaults to `gcc`.
It is also possible to statically link with `libcmp.a`, using `STATIC_LIBCMP`.
For further details on optional environment variables,
see the [`Makefile_v1`](Makefile_v1) and [`Makefile_src`](Makefile_src).


## Building

Build the software with
```
make
```
The result is in, for instance, `./libgencmp.so.2.0`.
This also builds all required dependencies
(such as `libsecutils/libsecutils.so.2.0` and `cmpossl/libcmp.so.2.0`)
and an application (`./cmpClient`) that is intended
for demonstration, test, and exploration purposes.

When getting the compiler error: `'openssl/openssl_backport.h' file not found`
likely `include/genericCMPClient_config.h` is outdated
and contains `#define USE_LIBCMP` although the environment variable `USE_LIBCMP`
is not set. In such situations, `make -f Makfile_v1 clean` helps to reset it to a consistent state.


### Installing and uninstalling

The software can be installed with, e.g.,
```
sudo make install
```
and uninstalled with
```
sudo make uninstall
```

The destination is `/usr`, unless specified otherwise by `DESTDIR` or `ROOTFS`.


### Cleaning up

`make clean` removes part of the artifacts, while
`make clean_all` removes everything produced by `make` and `CMake`.

## Building Debian packages for use also with Ubuntu

This repository can build the following binary and source packages.

* `libgencmp` - the shared library
* `libgencmp-dev` - development headers and documentation
* `cmpclient` - simple command-line application with its documentation
* `libgencmp*Source.tar.gz` -- source tarball

The recommended way is to use CPack with the files produced by CMake as follows:
```
make deb
```
which requries the `file` utility.

Alternatively, [`Makefile_v1`](Makefile_v1) may be used like this:
```
make -f Makefile_v1 deb
```
In this case, the resulting packages are placed in the parent directory (`../`),
and requires the following Debian packages:
* `debhelper` (needed for `dh`)
* `devscripts` (needed for `debuild`)
* `libssl-dev`
<!--
* `libsecutils-dev`
* `libcmp-dev` (if used)
--->

The Debian packages may be installed for instance as follows:
```
sudo dpkg -i libgencmp*deb cmpclient_*.deb
```


## Using the demo client

The CMP demo client is implemented in [`src/cmpClient.c`](src/cmpClient.c)
as part of the CLI.

For simple test invocations the Insta Certifier Demo CA server may be used,
for instance as follows:
```
openssl ecparam -genkey -name prime256v1 -out test.key.pem
cmpClient -config "" -server pki.certificate.fi:8700/pkix/ \
  -recipient "/C=FI/O=Insta Demo/CN=Insta Demo CA" \
  -secret pass:insta -ref 3078 \
  -cmd cr -newkey test.key.pem -subject "/CN=test" -certout test.cert.pem
openssl x509 -noout -text -in test.cert.pem
```
As the CMP client interacts via HTTP with an external CMP server, depending
on your network you may need to set the environment variable `http_proxy`.

A demo making use of all supported CMP commands can be executed with
```
make -f Makefile_v1 demo
```
The demo can be run using the online Insta Demo CA, which is the default,
or using an included Docker instance of the EJBCA that can be launched locally:
```
make -f Makefile_v1 demo_EJBCA
```

or using the reference playground CA operated by Siemens over a test cloud CA:

```
make -f Makefile_v1 demo_CloudCA
```

Among others, successful execution should produce a new certificate at `creds/operational.crt`.
You can view this certificate for instance by executing
```
openssl x509 -noout -text -in creds/operational.crt
```


## Using the CLI-based client

The Command-Line Interface (CLI) of the CMP client is implemented in
[`src/cmpClient.c`](src/cmpClient.c).
It supports most of the features of the genCMPClient library.
The CLI use with the available options are documented in [`cmpClient.pod`](doc/cmpClient.pod).

CLI-based tests using the external Insta Demo CA may be invoked using
```
make -f Makefile_v1 test_Insta
```
where the PROXY environment variable may be used to override the default
in order to reach the Insta Demo CA.


## Using the library in own applications

For building the library (and optionally the CLI application)
as part of other builds, it is recommended to use Debian packages or CMake.

Another possibility is to use [`Makefile_v1`](Makefile_v1),
for instance as given in the example outer [`Makefile.mk`](Makefile.mk).

For compiling applications using the library,
you will need to `#include` the header file [`genericCMPClient.h`](include/genericCMPClient.h)
and add the directories [`include`](include/) and
[`libsecutils/include`](https://github.com/siemens/libsecutils/blob/master/include/) to your C headers path.
When the intermediate library `libcmp` is used, you need to
add also the directory [`cmpossl/include/cmp`](https://github.com/mpeylo/cmpossl/tree/cmp/include/cmp/),
define the C macro `USE_LIBCMP`, and
make sure that any OpenSSL header files included have the same version
as the one used to build `libcmp`.

For linking you will need to
refer the linker to the CMP and Security Utilities libraries,
e.g., `-lsecutils -lgencmp`.
When the intermediate library `libcmp` is used, `-lcmp` is needed additionally.
Add the directories (e.g., with the linker option `-L`) where they can be found.
See also the environment variable `OUT_DIR`.
Consider using also linker options like `-Wl,-rpath=.`
for helping the Linux loader find the libraries at run time.

Also make sure that the OpenSSL libraries
(typically referred to via `-lssl -lcrypto`) are in your library path and
(the version of) the libraries found there by the linker match the header files found by the compiler.

All this is already done for the cmp client application.


## Disclaimer

This software including associated documentation is provided ‘as is’.
Effort has been spent on quality assurance, but there are no guarantees.


## License

This work is licensed under the terms of the Apache Software License 2.0.
See the [LICENSE.txt](LICENSE.txt) file in the top-level directory.

SPDX-License-Identifier: Apache-2.0
