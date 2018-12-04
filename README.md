This is the code repository for the cross-division generic CMP client library.


# Getting the library

You can clone the git repository with
```
git clone git@code.siemens.com:product-pki/genCMPClient.git
cd genCMPClient
git submodule update --init
```

This will download also the underlying [CMPforOpenSSL extension to OpenSSL](https://github.com/mpeylo/cmpossl) and
the [Security Utilities (SecUtils)](https://code.siemens.com/mo_mm_linux_distribution/securityUtilities) library
(which has some further, subordinate dependencies, namely, interface and test submodules).


# Building the library

Both the CMP library and the SecUtil library assume that OpenSSL (with any version >= 1.0.2) is already installed.
By default its headers will be searched for in `/usr/include` and its shared objects in `/usr/lib`.
You may point the environment variable `OPENSSL_DIR` to an alternative OpenSSL installation.

In the newly created directory `genCMPClient` you can build the library simply with `make`.
The result is in, for instance, `./libgencmpcl.so`.
This also builds all required dependencies and a demo application.

**Imporant Note:** by default, the Security Utilities make use of the [Unified Trust Anchor (UTA) API](https://code.siemens.com/hermann.seuschek/uta_api) library
for secure device-level storage of key material for confidentiality and integriy protection of files.
Since this library is not yet generally available Siemens-wide the SecUtils are so far integrated in a way that the use of the UTA lib is disabled (via `SEC_NO_UTA=1`).
This means that secure storage of protection credentials for private keys and trusted certificates needs to be solved by other means.


# Using the library

Have a look at the demo client in [`src/cmpClientDemo.c`](src/cmpClientDemo.c).
It can be executed with `make test` or manually like this:
```
export no_proxy=ppki-playground.ct.siemens.com
wget "http://ppki-playground.ct.siemens.com/ejbca/publicweb/webdist/certdist?cmd=crl&format=PEM&issuer=CN%3dPPKI+Playground+Infrastructure+Issuing+CA+v1.0%2cOU%3dCorporate+Technology%2cOU%3dFor+internal+test+purposes+only%2cO%3dSiemens%2cC%3dDE" -O certs/crls/PPKIPlaygroundInfrastructureIssuingCAv10.crl
./cmpClientDemo
```

You will need to include in your application sources the file [`genericCMPClient.h`](include/genericCMPClient.h).

For compiling you will need to add the directories `include`, `include_cmp`, and `securityUtilities/include` to your C headers path and
ake sure that any OpenSSL header files included have the same version as the one used to build the standalone CMP library `libcmp`.

For linking you will need to add the directories `.` and `securityUtilities` to your library path and
refer the linker to the CMP and SecUtils libraries, e.g., `-lcmp -lSecUtils`.
Also make sure that the OpenSSL libraries (typically referred to via `-lssl -lcrypto`) are in your library path and
(the version) of the libraries found there by the linker match the header files found by the compiler.

All this is already done for the demo application.


# Documentation of the library

The Generic CMP client API specification is available in the [doc](doc/) folder.

The Doxygen documentation of the underlying Security Utilities library is going to be available
via a link in its [README file](https://code.siemens.com/mo_mm_linux_distribution/securityUtilities/blob/development/README.md).

# Disclaimer

This software including associated documentation is provided ‘as is’ in a preliminary state.
Our development procedures and processes are not sufficient to assure product-grade software quality.
Although some effort has already beeen spent on quality assurance,
it is explicitly not guaranteed that all due measures for productive software have been implemented.
Please also note that the [Siemens Inner Source License](LICENSE) applies.
