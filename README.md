This is the code repository for the cross-division generic CMP client library based on CMPforOpenSSL.


# Getting the library

Clone the git repository with
```
git clone --recurse-submodules git@code.siemens.com:product-pki/genCMPClient.git
```

This will download also the underlying [Security Utilities (SecUtils)](https://code.siemens.com/mo_mm_linux_distribution/securityUtilities) library,
including the required [CMPforOpenSSL](https://github.com/mpeylo/cmpossl) extension to OpenSSL (currently version 1.1.0.f) and some further, minor dependencies (namely, interface and test submodules).


# Building the library

Build the library with `make`.
This also builds its submodule(s) and demo application.

**Imporant Note:** the Security Utilities usually make use of the [Unified Trust Anchor (UTA) API](https://code.siemens.com/hermann.seuschek/uta_api) library for device-level secure storage of passwords and integriy protection of files.
Since this library is not yet generally available Siemens-wide the SecUtils are so far integrated in a way that the use of the UTA lib is disabled (via `SEC_NO_UTA=1`). This means that secure storage of protection credentials for private keys and trusted certificates needs to be solved by other means.


# Using the library

Have a look at the demo client in [`src/cmpClientDemo.c`](src/cmpClientDemo.c), which can be executed with `make test`.

For compiling you will need to add the directories `include` and `securityUtilities/include` to your C headers path and include in your application sources the file [`genericCMPClient.h`](include/genericCMPClient.h).
For linking you will need to add the directories `lib` and `securityUtilities` to your library path and refer the linker to the SecUtils library, e.g., `-lSecUtils`. 
All this is already done for the demo application.


# Documentation of the library

The API specification is available at **TBD** (so far: CrossDivision_CMP-Client\Architecture\Generic_CMP_client_API_v1.1.pdf).

The Doxygen documentation of the underlying Security Utilities library is available at **TBD**.
