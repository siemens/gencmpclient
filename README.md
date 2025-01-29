# generic CMP client

This is a generic CMP client library with high-level API
and associated CLI-based demo client, tests, and documentation.

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

See the [CHANGELOG.md](CHANGELOG.md) file in the top-level directory.


## Documentation

The Generic CMP client API specification and CLI documentation are available in the [`doc`](doc/) folder.

The Doxygen documentation of the underlying Security Utilities library is available
via a link in its [README file](https://github.com/siemens/libsecutils/blob/master/README.md).


## Prerequisites

This software should work with any flavor of Linux, including [Cygwin](https://www.cygwin.com/),
also on a virtual machine or the Windows Subsystem for Linux ([WSL](https://docs.microsoft.com/windows/wsl/about)).

The following network and development tools are needed or recommended.
* Git (for getting the software, tested with versions 2.7.2, 2.11.0, 2.20, 2.30.2)
* CMake (for using [`CMakeLists.txt`](CMakeLists.txt), tested with version 3.18.4)
* GNU make (tested with versions 4.1, 4.2.1, 4.3)
* GNU C compiler (gcc, tested with versions 5.4.0, 7.3.0, 8.3.0, 10.0.1, 10.2.1)
* wget (for running the demo, tested with versions 1.17, 1.18, 1.20, 1.21)
* Perl (for running the tests, tested with version 5.32.1)

The following OSS components are used.
* OpenSSL development edition; supported versions: 1.1.1, 3.0, 3.1
* [Security Utilities (libsecutils)](https://github.com/siemens/libsecutils)
* [CMPforOpenSSL](https://github.com/mpeylo/cmpossl),
  a CMP+HTTP extension to OpenSSL, needed at least when using OpenSSL 1.x

For instance, on a Debian system the prerequisites may be installed simply as follows:
```
sudo apt install cmake libssl-dev libc-dev linux-libc-dev
```
while `apt install git make gcc wget` usually is not needed as far as these tools are pre-installed.

As a sanity check you can execute in a shell:
```
git clone git@github.com:siemens/genCMPClient.git
cd genCMPClient
make -f OpenSSL_version.mk
```

This should output on the console something like
```
cc [...] OpenSSL_version.c -lcrypto -o OpenSSL_version
OpenSSL 3.0.8 7 Feb 2023 (0x30000080)
```

You might need to set the variable `OPENSSL_DIR` first as described below, e.g.,
```
export OPENSSL_DIR=/usr/local
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
git clone git@github.com:siemens/genCMPClient.git
cd genCMPClient
make -f Makefile_v1 get_submodules  
```

This will fetch also the underlying [CMPforOpenSSL extension to OpenSSL](https://github.com/mpeylo/cmpossl) and
the [Security Utilities (libsecutils)](https://github.com/siemens/libsecutils) library.

For using the project as a git submodule,
do for instance the following in the directory where you want to integrate it:
```
git submodule add git@github.com:siemens/gencmpclient.git
```

When you later want to update your local copy of all relevant repositories it is sufficient to invoke
```
make -f Makefile_v1 update
```


## Configuring and building

The generic CMP client (as well as its underlying libraries)
assumes that OpenSSL is already installed,
including the C header files needed for development
(as provided by, e.g., the Debian/Ubuntu package `libssl-dev`).

By default any OpenSSL installation available on the system is used.
Set the optional environment variable `OPENSSL_DIR` to specify the
absolute (or relative to `../`) path of the OpenSSL installation to use, e.g.:
```
export OPENSSL_DIR=/usr/local
```
In case its libraries are in a different location, set also `OPENSSL_LIB`, e.g.:
```
export OPENSSL_LIB=$OPENSSL_DIR/lib
```

Since version 2, it is recommended to use CMake to produce the `Makefile`,
for instance as follows:
```
cmake .
```

For backward compatibility it is also possible to use instead of CMake
pre-defined [`Makefile_v1`](Makefile_v1); to this end symlink it to `Makefile`:
```
ln -s Makefile_v1 Makefile
```
or use for instance `make -f Makefile_v1`.

By default `Makefile_v1` behaves as if
```
OPENSSL_DIR=/usr
```
was given, such that the OpenSSL headers will be searched for in `/usr/include`
and its shared objects in `/usr/lib` (or `/usr/bin` for Cygwin).

When using CMake, `cmake` must be (re-)run
after setting or unsetting environment variables.

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
For further details on optional environment variables,
see the [`Makefile_v1`](Makefile_v1) and [`Makefile_src`](Makefile_src).

Build the software with
```
make
```
By default, builds are done in Debug mode.
For Release mode use `-DCMAKE_BUILD_TYPE=Release` or `NDEBUG=1`.
For switching to Debug mode, use `-DCMAKE_BUILD_TYPE=Debug` and unset `NDEBUG`.

The result is in, for instance, `./libgencmp.so.2.0`.
This also builds all required dependencies
(such as `libsecutils/libsecutils.so.2.0` and `cmpossl/libcmp.so.2.0`)
and an application (`./cmpClient`) that is intended
for demonstration, test, and exploration purposes.


### Installing and uninstalling

The software can be installed with
```
make install
```
and uninstalled with
```
make uninstall
```

The destination is `/usr/local`, unless specified otherwise by `ROOTFS`.

## Building Debian packages

This repository can build the following Debian packages.

* `libgencmp` - the shared library
* `libgencmp-dev` - development headers
* `cmpclient` - simple command-line application

To build the Debian packages, the following dependencies need to be installed:
* `debhelper` (needed for `dh`)
* `devscripts` (needed for `debuild`)
* `libssl-dev`
* `libsecutils-dev`
* `libcmp-dev` (if used)

Currently [`CMakeLists.txt`](CMakeLists.txt) does not support Debian packaging.
Yet [`Makefile_v1`](Makefile_v1) may be used like this:
```
ln -s Makefile_v1 Makefile
make deb
```
On success, the packages are placed in the parent directory (`../`).
They may be installed for instance as follows:
```
sudo dpkg -i ../cmpclient_*.deb ../libgencmp_*deb libsecutils_*.deb libcmp_*deb
```
If you built with OpenSSL 1.x, add the `--ignore-depends=libssl3` option.


## Using the demo client

The CMP demo client is implemented in [`src/cmpClient.c`](src/cmpClient.c)
as part of the CLI.

For simple test invocations the Insta Certifier Demo CA server may be used,
for instance as follows:
```
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
```
make -f Makefile_v1 demo   
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
as part of other builds, it is recommended to call the `Makefile`,
for instance as given in the example outer [`Makefile.mk`](Makefile.mk).

For compiling applications using the library,
you will need to `#include` the header file [`genericCMPClient.h`](include/genericCMPClient.h)
and add the directories [`include`](include/) and
[`libsecutils/include`](https://github.com/siemens/libsecutils/blob/master/include/) to your C headers path.
Wenn using OpenSSL 1.x, you need to
add also the directory [`cmpossl/include/cmp`](https://github.com/mpeylo/cmpossl/tree/cmp/include/cmp/),
define the C macro `CMP_STANDALONE`, and
make sure that any OpenSSL header files included have the same version
as the one used to build the standalone CMP library `libcmp`.

For linking you will need to
refer the linker to the CMP and Security Utilities libraries,
e.g., `-lsecutils -lcmp -lgencmp`.
When using OpenSSL 1.x, `-lcmp` is needed additionally.
Add the directories (e.g., with the linker option `-L`) where they can be found.
See also the environment variable `OUT_DIR`.
For helping the Linux loader to find the libraries at run time,
it is recommended to set also linker options like `-Wl,-rpath=.`.

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
