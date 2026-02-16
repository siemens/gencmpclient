genCMPClient changes
====================

genCMPClient 2.2
----------------

* Released on Mon Feb 16 16:17:18 2026 +0100
* Support building core library natively under Windows
* Add build option `GENCMP_STATIC_LIB`
* Further improve CMake etc. build support, CI, demo, and documentation
* Make sure that suitable X.509 extensions are placed in cert request template of KUR messages
* Fix various issues and OpenSSL version incompatibilities
* Disable demo_Insta because Insta Demo CA is defunct since end of 2025


genCMPClient 2.1
----------------

* Released on Fri, 17 Oct 2025 10:53:28 +0200
* Improve use of OpenSSL crypto providers and OSSL_STORE for credential loading
* Further improve CMake etc. build support, CI, demo, and documentation
* Fix various small bugs and OpenSSL version incompatibilities
* Deprecate use of intermediate libcmp, which is no more needed since OpenSSL 3.5

genCMPClient 2.0
----------------

* Released on Fri, 14 Apr 2023 09:09:05 +0200
* Include all features of the Lightweight CMP Profile
* Improve CMake and Debian packaging support
* Fix various small bugs and OpenSSL version incompatibilities

genCMPClient 1.0
----------------

* Initial release  Fri, 17 Sep 2021 11:41:32 +0200
