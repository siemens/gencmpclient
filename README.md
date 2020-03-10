# generic CMP client

This is the code repository for the cross-division generic CMP client library
with associated CLI-based demo/test client and documentation.

## Status

* All features agreed with the participating Siemens business units
have been implemented and documented in FY 2019.
* Several hundreds of test cases have been compiled and executed successfully.
* Open-source clearing has been finished in Feb 2020.
* Maintenance (i.e., minor updates and fixes, also to the documentation)
is ongoing, at least for FY 2020.


## Prerequisites

This software should work with any flavor of Linux, including [Cygwin](https://www.cygwin.com/),
also on a virtual machine or the Windows Subsystem for Linux ([WSL](https://docs.microsoft.com/windows/wsl/about)).

The following network and development tools are required.
* SSH (tested with OpenSSH 7.2, 7.4, and 7.9)
* wget (tested with versions 1.17, 1.18, and 1.20)
* Git (tested with versions 2.7.2, 2.11.0, and 2.20)
* GNU make (tested with versions 4.1 and 4.2.1)
* GNU C compiler (tested with versions 5.4.0, 7.3.0, and 8.3.0)
* OpenSSL (version >= 1.0.2) with header files

For instance, on a Debian system these may be installed as follows:
```
sudo apt install libssl-dev
```
while `apt install ssh wget git make gcc` usually is not needed because these tools are pre-installed.

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
cc OpenSSL_version.c -lcrypto -o OpenSSL_version
OpenSSL 1.1.1c  28 May 2019 (0x1010103f)
rm -f OpenSSL_version
```


## Getting the software

For accessing `git@code.siemens.com` you will need an SSH client with credentials allowing to read from that repository.

For accessing `https://github.com/mpeylo/cmpossl` from the Siemens intranet you may need to set up an HTTP proxy, for instance:
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
the [Security Utilities (SecUtils)](https://code.siemens.com/mo_mm_linux_distribution/securityUtilities) library
(which has some recursive submodules, of which only `libs/interfaces` is fetched).


## Building the software

The generic CMP client (and also its underlying CMP and SecUtils libraries) assumes that OpenSSL (with any version >= 1.0.2) is already installed,
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

The result is in, for instance, `./libgencmpcl.so`.
This also builds all required dependencies (such as `./libcmp.so` and `./securityUtilities/libSecUtils.so`) and an application (`./cmpClient`) for demonstration, test, and exploration purposes.

**Important Note:** by default, the Security Utilities make use of the
[Unified Trust Anchor (UTA) API](https://code.siemens.com/hermann.seuschek/uta_api) library
for secure device-level storage of key material for confidentiality and integrity protection of files.
Since the URA library is not yet generally available Siemens-wide the SecUtils are so far integrated in a way that the use of the UTA lib is disabled (via `SEC_NO_UTA=1`).
This means that secure storage of protection credentials for private keys and trusted certificates needs to be solved by other means.


## Using the demo client

The CMP demo client is implemented in [`src/cmpClient.c`](src/cmpClient.c).
It can be executed with
```
make test
```

or manually like this:

```
export no_proxy=ppki-playground.ct.siemens.com
wget "http://ppki-playground.ct.siemens.com/ejbca/publicweb/webdist/certdist?cmd=crl&format=PEM&issuer=CN%3dPPKI+Playground+Infrastructure+Issuing+CA+v1.0%2cOU%3dCorporate+Technology%2cOU%3dFor+internal+test+purposes+only%2cO%3dSiemens%2cC%3dDE" -O creds/crls/PPKIPlaygroundInfrastructureIssuingCAv10.crl
./cmpClient
```

Among others, successful execution should produce a new certificate at `creds/new.crt`.
You can view this certificate for instance by executing
```
openssl x509 -noout -text -in creds/new.crt
```

The demo client allows also to update and revoke the enrolled certificate, like this:
```
./cmpClient update
./cmpClient revoke
```

The demo client may also interact with the external Insta Certifier Demo CA via
```
export http_proxy=de.coia.siemens.net:9400  # adapt to your needs
make test_insta
```


## Using the CLI-based test client

The Comand Line Interface (CLI) of the CMP client is implemented in [`src/cmpClient.c`](src/cmpClient.c).
It supports most of the features of the genCMPClient library.
The CLI use with the available options are documented in [`cmpClient-cli.md`](doc/cmpClient-cli.md).

CLI-based tests may be invoked using
```
http_proxy=de.coia.siemens.net:9400 make test_Insta
```
assuming the proxy is needed and sufficient to reach the external Insta CA
or
```
make test_SimpleLra
```
assuming a local SimpleLra instance is running and forwards requests to the Siemens Product PKI (PPKI) Playground server.


## Using the library in own applications

For compiling the library itself you will need to add the directories `include`, `include_cmp`, and `securityUtilities/include` to your C headers path and
make sure that any OpenSSL header files included have the same version as the one used to build the standalone CMP library `libcmp`.

For linking you will need to add the directories `.` and `securityUtilities` to your library path and
refer the linker to the CMP and SecUtils libraries, e.g., `-lcmp -lSecUtils`.
Also make sure that the OpenSSL libraries (typically referred to via `-lssl -lcrypto`) are in your library path and
(the version) of the libraries found there by the linker match the header files found by the compiler.

For building your application you will need to `#include` the header file [`genericCMPClient.h`](include/genericCMPClient.h) and link using `-lgencmpcl`.

All this is already done for the cmp client application.


## Documentation

The Generic CMP client API specification and CLI documentation are available in the [doc](doc/) folder.

A recording of the tutorial held via Circuit on 2018-Dec-13 is available [here](https://myvideo.siemens.com/media/1_f7bjtdba).

The Doxygen documentation of the underlying Security Utilities library is going to be available
via a link in its [README file](https://code.siemens.com/mo_mm_linux_distribution/securityUtilities/blob/development/README.md).


## Disclaimer

This software including associated documentation is provided ‘as is’ in a preliminary state.
Our development procedures and processes are not sufficient to assure product-grade software quality.
Although some effort has already been spent on quality assurance,
it is explicitly not guaranteed that all due measures for productive software have been implemented.
Therefore we cannot provide any guarantees about this software and do not take any liability for it.

Please also note that the [Siemens Inner Source License](LICENSE) applies to
the overall repository and the Apache License, Version 2.0 applies to the code.
