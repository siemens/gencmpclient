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
This also builds all required dependencies and a simple demo application.

**Imporant Note:** by default, the Security Utilities make use of the [Unified Trust Anchor (UTA) API](https://code.siemens.com/hermann.seuschek/uta_api) library
for secure device-level storage of key material for confidentiality and integriy protection of files.
Since this library is not yet generally available Siemens-wide the SecUtils are so far integrated in a way that the use of the UTA lib is disabled (via `SEC_NO_UTA=1`).
This means that secure storage of protection credentials for private keys and trusted certificates needs to be solved by other means.


# Using the library

Have a look at the demo client in [`src/cmpClientDemo.c`](src/cmpClientDemo.c).
The simple example application can be executed directly as `./cmpClientDemo` or with `make test`.

You will need to include in your application sources the file [`genericCMPClient.h`](include/genericCMPClient.h) before including any OpenSSL header files.
For compiling you will need to add the directories `include` and `securityUtilities/include` to your C headers path and
add `-isystem include_cmp` to your `CFLAGS` (such that the directory `./include_cmp` is searched before any OpenSSL include paths).
For linking you will need to add the directories `.` and `securityUtilities` to your library path and
refer the linker to the CMP and SecUtils libraries, e.g., `-lcmp -lSecUtils` (and also refer to OpenSSL via `-lssl -lcrypto`).
All this is already done for the demo application.


# Documentation of the library

The API specification is available at **TBD** (so far: CrossDivision_CMP-Client\Architecture\Generic_CMP_client_API_v1.1.pdf).

The Doxygen documentation of the underlying Security Utilities library is available at **TBD**.
