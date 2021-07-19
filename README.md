# generic CMP client

This is the code repository for the cross-division generic CMP client library
with associated CLI-based demo/test client and documentation.


## Status

* Open-sourced in September 2021x

## Prerequisites

This software should work with any flavor of Linux, including [Cygwin](https://www.cygwin.com/),
also on a virtual machine or the Windows Subsystem for Linux ([WSL](https://docs.microsoft.com/windows/wsl/about)).

The following network and development tools are required.
* SSH (tested with OpenSSH 7.2, 7.4, and 7.9)
* wget (tested with versions 1.17, 1.18, and 1.20)
* Git (tested with versions 2.7.2, 2.11.0, and 2.20)
* GNU make (tested with versions 4.1 and 4.2.1)
* GNU C compiler (tested with versions 5.4.0, 7.3.0, 8.3.0, and 10.0.1)
* OpenSSL development edition (tested with versions 1.0.2u, 1.1.0, 1.1.1, and 3.0.0-beta2-dev)

For instance, on a Debian system these may be installed as follows:
```
sudo apt install libssl-dev
```
while `apt install ssh wget git make gcc` usually is not needed as far as these tools are pre-installed.

As a sanity check you can execute in a shell:
```
git clone git@github.com:siemens/genCMPClient.git
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
OpenSSL 1.1.1d  10 Sep 2019 (0x1010104f)
rm -f OpenSSL_version
```


## Getting the software

For accessing the code repositories on GitHub you may need
an SSH client with suitable credentials or an HTTP proxy setp, for instance:
```
export https_proxy=http://proxy.my-company.com:8080
```

You can clone the git repository and its submodules with
```
git clone git@github.com:siemens/genCMPClient.git
cd genCMPClient
make get_submodules
```

This will fetch also the underlying [CMPforOpenSSL extension to OpenSSL](https://github.com/mpeylo/cmpossl) and
the [Security Utilities (libsecutils)](https://github.com/siemens/libsecutils) library
(which has some recursive submodules, of which only `libs/interfaces` is fetched).

When you later want to update your local copy of all relevant repositories it is sufficient to invoke
```
make update
```


## Building the software

The generic CMP client (and also its underlying CMP and Security Utilities libraries) assumes that OpenSSL (with any version >= 1.1.0) is already installed,
including the C header files needed for development (as provided by, e.g., the Debian/Ubuntu package `libssl-dev`).
By default the OpenSSL headers will be searched for in `/usr/include` and its shared objects in `/usr/lib` (or `/usr/bin` for Cygwin).
You may point the environment variable `OPENSSL_DIR` to an alternative OpenSSL installation, e.g.:
```
export OPENSSL_DIR=/usr/local
```

In the newly created directory `genCMPClient` you can build the software simply with
```
make
```
where the CC environment variable may be set as needed; it defaults to 'gcc'.
Also the ROOTFS environment variable may be set, e.g., for cross compiliation.

The result is in, for instance, `./libgencmpcl.so`.
This also builds all required dependencies (such as `./libcmp.so` and `./libsecutils.so`) and an application (`./cmpClient`) for demonstration, test, and exploration purposes.

## Using the demo client

The CMP demo client is implemented in [`src/cmpClient.c`](src/cmpClient.c).
It can be executed with
```
make demo
```

or manually like this:

```
./cmpClient
```

Among others, successful execution should produce a new certificate at `creds/operational.crt`.
You can view this certificate for instance by executing
```
openssl x509 -noout -text -in creds/operational.crt
```

The demo client allows also to update and revoke the enrolled certificate, like this:
```
./cmpClient update
./cmpClient revoke
```

The demo client may also interact with the external Insta Certifier Demo CA via
```
export http_proxy=  # adapt to your needs
make demo_Insta
```


## Using the CLI-based client

The Comand Line Interface (CLI) of the CMP client is implemented in [`src/cmpClient.c`](src/cmpClient.c).
It supports most of the features of the genCMPClient library.
The CLI use with the available options are documented in [`cmpClient-cli.md`](doc/cmpClient-cli.md).

CLI-based tests using the external Insta Demo CA may be invoked using
```
make test_Insta
```
where the PROXY environment variable may be used to override the default in order to reach the Insta CA.

## Using the library in own applications

For compiling the library itself you will need to add the directories `include`, `include_cmp`, and `libsecutils/include` to your C headers path and
make sure that any OpenSSL header files included have the same version as the one used to build the standalone CMP library `libcmp`.

For linking you will need to add the directories `.` and `libsecutils` to your library path and
refer the linker to the CMP and Securit Utilities libraries, e.g., `-lcmp -lsecutils`.
Also make sure that the OpenSSL libraries (typically referred to via `-lssl -lcrypto`) are in your library path and
(the version) of the libraries found there by the linker match the header files found by the compiler.

For building your application you will need to `#include` the header file [`genericCMPClient.h`](include/genericCMPClient.h) and link using `-lgencmpcl`.

All this is already done for the cmp client application.


## Documentation

The Generic CMP client API specification and CLI documentation are available in the [doc](doc/) folder.

The Doxygen documentation of the underlying Security Utilities library is going to be available
via a link in its [README file](https://github.com/siemens/libsecutils/blob/master/README.md).


## Disclaimer

This software including associated documentation is provided ‘as is’ in a preliminary state.
Our development procedures and processes are not sufficient to assure product-grade software quality.
Although some effort has already been spent on quality assurance,
it is explicitly not guaranteed that all due measures for productive software have been implemented.
Therefore we cannot provide any guarantees about this software and do not take any liability for it.
