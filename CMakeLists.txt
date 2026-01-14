cmake_minimum_required(VERSION 3.18)

project(libgencmp)
set(LIBGENCMP_NAME gencmp)

if(NOT DEFINED GENCMPCLIENT_VERSION)
  set(GENCMPCLIENT_VERSION_MAJOR 2)
  set(GENCMPCLIENT_VERSION_MINOR 1)
  set(GENCMPCLIENT_VERSION ${GENCMPCLIENT_VERSION_MAJOR}.${GENCMPCLIENT_VERSION_MINOR})
endif()
message(STATUS "generic CMP client version " ${GENCMPCLIENT_VERSION})

# set(CMAKE_VERBOSE_MAKEFILE ON)
# set(CMAKE_EXPORT_COMPILE_COMMANDS ON) # needed for sonarCloud scanner when using CMake

if(DEFINED ENV{GENCMP_NO_SECUTILS})
  message(STATUS "will build without libSecUtils and CLI")
  add_compile_definitions(GENCMP_NO_SECUTILS)
  set(GENCMP_NO_SECUTILS 1)
  set(GENCMP_NO_CLI 1)
endif()

if(DEFINED ENV{SECUTILS_NO_TLS})
  set(GENCMP_NO_TLS 1)
endif()
if(DEFINED ENV{GENCMP_NO_TLS})
  set(GENCMP_NO_TLS 1)
endif()
if(${GENCMP_NO_TLS})
  message(STATUS "will build without TLS support")
  add_compile_definitions(GENCMP_NO_TLS)
  add_compile_definitions(SECUTILS_NO_TLS)
endif()

# must do add_compile_options() before add_library() and add_executable() see
# https://stackoverflow.com/questions/40516794/cmake-not-applying-compile-option-using-add-compile-options
if(DEFINED ENV{NDEBUG} OR NOT CMAKE_BUILD_TYPE MATCHES Debug)
  if(DEFINED ENV{NDEBUG})
    message(STATUS "Setting build type to 'Release' because NDEBUG was set.")
  elseif(NOT CMAKE_BUILD_TYPE)
    message(STATUS "Setting build type to 'Release' by default.")
  endif()
  set(CMAKE_BUILD_TYPE Release  # automatically leads to CFLAGS += -DNDEBUG -O3
      CACHE STRING "Choose the type of build." FORCE)
else()
  set(CMAKE_BUILD_TYPE Debug  # automatically leads to CFLAGS += -g  # -O0 not added by default
      CACHE STRING "Choose the type of build." FORCE)
  set(SANITIZER_FLAGS -fsanitize=address,undefined -fno-sanitize-recover=all)
  add_compile_options(${SANITIZER_FLAGS})
  link_libraries(${SANITIZER_FLAGS})

  if(UNIX AND NOT APPLE)
    set(COVERAGE_FLAGS --coverage -fprofile-arcs)
    add_compile_options(${COVERAGE_FLAGS})
    link_libraries(${COVERAGE_FLAGS})
  endif()
endif()
message(STATUS "build mode: ${CMAKE_BUILD_TYPE}")

# improved from https://cmake.org/cmake/help/v3.6/module/FindOpenSSL.html
if(NOT "$ENV{OPENSSL_DIR}" STREQUAL "")
  get_filename_component(OPENSSL_ROOT_DIR "$ENV{OPENSSL_DIR}" ABSOLUTE)
  if(NOT TARGET OpenSSL::Crypto) # not already handled by superordinate module
    # invalidate defaults from CMakeCache.txt
    set(OPENSSL_VERSION "")
    set(OPENSSL_INCLUDE_DIR "")
    set(OPENSSL_LIB_SET FALSE)
    set(OPENSSL_CRYPTO_LIBRARY "")
    set(OPENSSL_SSL_LIBRARY "")
  endif()
endif()
if(NOT "$ENV{OPENSSL_DIR}" STREQUAL "" OR
   NOT TARGET OpenSSL::Crypto) # not already done by superordinate module
  if(${SECUTILS_NO_TLS})
    set(OPENSSL_COMPONENTS COMPONENTS Crypto)
  else()
    set(OPENSSL_COMPONENTS COMPONENTS Crypto SSL)
  endif()
  if(DEFINED OPENSSL_ROOT_DIR)
    if(NOT APPLE) # on macOS, work around find_package() not respecting HINTS and NO_DEFAULT_PATH
      find_package(OpenSSL HINTS "${OPENSSL_ROOT_DIR}" NO_DEFAULT_PATH ${OPENSSL_COMPONENTS})
    endif()
  else()
    find_package(OpenSSL ${OPENSSL_COMPONENTS})
  endif()
  STRING(REGEX REPLACE ";.*" "" OPENSSL_INCLUDE_DIR "${OPENSSL_INCLUDE_DIR}")
  if(NOT OPENSSL_INCLUDE_DIR)
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
  endif()
  if(NOT OPENSSL_VERSION)
    file(READ "${OPENSSL_INCLUDE_DIR}/openssl/opensslv.h" OPENSSLV_CONTENT)
    string(REGEX MATCH "OpenSSL ([0-9]+\\.[0-9]+\\.[0-9]+[^ ]*)" VERSION_MATCH "${OPENSSLV_CONTENT}")
    if(VERSION_MATCH)
      string(REGEX REPLACE "OpenSSL " "" OPENSSL_VERSION "${VERSION_MATCH}")
    else()
      set(OPENSSL_VERSION "(unknown)")
    endif()
  endif()
endif()
message(STATUS "using OpenSSL version ${OPENSSL_VERSION}")
message(STATUS "using OpenSSL inc dir ${OPENSSL_INCLUDE_DIR}")
if(NOT EXISTS "${OPENSSL_INCLUDE_DIR}/openssl")
  message(FATAL_ERROR "OpenSSL include directory does not exist: ${OPENSSL_INCLUDE_DIR}/openssl")
endif()
if(NOT TARGET OpenSSL::Crypto) # not already done by superordinate module
  set(OPENSSL_LIB "$ENV{OPENSSL_LIB}")
  if(NOT OPENSSL_LIB)
    if (NOT "$ENV{OPENSSL_DIR}" STREQUAL "")
      set(OPENSSL_LIB $ENV{OPENSSL_DIR})
    elseif(OPENSSL_CRYPTO_LIBRARY)
      get_filename_component(OPENSSL_LIB "${OPENSSL_CRYPTO_LIBRARY}" DIRECTORY)
    endif()
  endif()
  get_filename_component(OPENSSL_LIB "${OPENSSL_LIB}" ABSOLUTE)
  message(STATUS "using OpenSSL lib dir ${OPENSSL_LIB}")
  if(NOT EXISTS "${OPENSSL_LIB}")
    message(FATAL_ERROR "directory OPENSSL_LIB does not exist: ${OPENSSL_LIB}")
  endif()
  if(NOT TARGET OpenSSL::Crypto)
    add_library(OpenSSL::Crypto SHARED IMPORTED)
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_LIB}/libcrypto${CMAKE_SHARED_LIBRARY_SUFFIX}")
    set_target_properties(OpenSSL::Crypto PROPERTIES IMPORTED_LOCATION ${OPENSSL_CRYPTO_LIBRARY})
    set_target_properties(OpenSSL::Crypto PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}")
  endif()
  if(NOT TARGET OpenSSL::SSL)
    add_library(OpenSSL::SSL SHARED IMPORTED)
    set(OPENSSL_SSL_LIBRARY "${OPENSSL_LIB}/libssl${CMAKE_SHARED_LIBRARY_SUFFIX}")
    set_target_properties(OpenSSL::SSL PROPERTIES IMPORTED_LOCATION ${OPENSSL_SSL_LIBRARY})
    set_target_properties(OpenSSL::SSL PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}")
  endif()
  if(NOT DEFINED OPENSSL_FOUND)
    set(OPENSSL_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})
  endif()
endif()
message(STATUS "using OpenSSL library ${OPENSSL_CRYPTO_LIBRARY}, ${OPENSSL_SSL_LIBRARY}")
if(NOT EXISTS "${OPENSSL_CRYPTO_LIBRARY}")
  message(FATAL_ERROR "OpenSSL crypto library file does not exist: ${OPENSSL_CRYPTO_LIBRARY}")
endif()

# workaround for using local OpenSSL builds by default expecting that
# its dynamic libs have been installed in ./${LIB} when using the libs
# see for binaries dynamically linked to OpenSSL the output of ${LDD} <binary>
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
  set(USERS "^(\w:)?\\Users\\")
  set(LIB "bin")
else()
  set(USERS "^/(home|Users)/")
  set(LIB "lib")
endif()
string(REGEX MATCH ${USERS} MATCHED "${OPENSSL_LIB}")
if(NOT "${MATCHED}" STREQUAL "" AND NOT EXISTS "${OPENSSL_LIB}/${LIB}")
  execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink "." "${OPENSSL_LIB}/${LIB}")
  # since CMake 3.13, this works also for Windows
endif()

string(REGEX MATCH "^([0-9]+)" OPENSSL_VERSION_MAJOR "${OPENSSL_VERSION}")
if(NOT OPENSSL_VERSION_MAJOR)
  MESSAGE(WARNING "Cannot detect OpenSSL version, assuming at least 3.0")
elseif("${OPENSSL_VERSION_MAJOR}" LESS "3")
  set(OPENSSL_VERSION_BELOW_3 1)
endif()
if(OPENSSL_VERSION_BELOW_3)
  set(GENCMP_NO_CLI 1)
  MESSAGE(WARNING "Cannot build cmpClient CLI app with OpenSSL < 3.0")
endif()
if(DEFINED ENV{USE_LIBCMP} OR OPENSSL_VERSION_BELOW_3)
  set(USE_LIBCMP 1)
  message(STATUS "using libcmp, which is deprecated")
endif()

set(SRC_DIR ${PROJECT_SOURCE_DIR}/src)
set(INC_DIR ${PROJECT_SOURCE_DIR}/include)
if(DEFINED USE_LIBCMP)
  set(CMPOSSL_INC_DIR ${PROJECT_SOURCE_DIR}/cmpossl/include)
endif()

include_directories(
  ${INC_DIR}
)
if(DEFINED USE_LIBCMP)
  include_directories(SYSTEM ${CMPOSSL_INC_DIR}/cmp)
  include_directories(SYSTEM ${CMAKE_SYSROOT}/usr/include/cmp)
endif()

# must not add the system OpenSSL include dir before ${CMPOSSL_INC_DIR}/cmp etc.
include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})

configure_file(${INC_DIR}/genericCMPClient_config.h.in ${INC_DIR}/genericCMPClient_config.h)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
  # help CPackDeb please dpkg-shlibdeps
  if(${CMAKE_VERSION} VERSION_GREATER_EQUAL "3.20.0")
    set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS_PRIVATE_DIRS
        ${CMAKE_CURRENT_BINARY_DIR} "${CMAKE_CURRENT_BINARY_DIR}/cmpossl"
        "${CMAKE_CURRENT_BINARY_DIR}/libsecutils/src/libsecutils")
  else()
    set(CMAKE_INSTALL_RPATH # must be done before add_executable()
        "../${CMAKE_INSTALL_LIBDIR}")
  endif()
endif()

# must do add_compile_options() before add_library() and add_executable() see
# https://stackoverflow.com/questions/40516794/cmake-not-applying-compile-option-using-add-compile-options
if(CMAKE_BUILD_TYPE MATCHES Debug)
  add_compile_options(-O0)  # workaround for -O0 not being added by default when libSecUtils is not used
endif()


add_compile_definitions(DEBUG_UNUSED)
add_compile_definitions(PEDANTIC)
add_compile_options(-pedantic) # -Werror is enabled only for development and CI, using Makefile_v1 without NDEBUG
add_compile_options(
  -Wall -Woverflow -Wextra -Wmissing-prototypes -Wstrict-prototypes -Wswitch
  -Wsign-compare -Wformat -Wtype-limits -Wundef -Wconversion -Wunused-parameter)
add_compile_options(-Wno-c99-extensions -Wno-language-extension-token -Wno-declaration-after-statement -Wno-expansion-to-defined)
if(NOT DEFINED GENCMP_NO_SECUTILS)
  add_compile_options(-Wno-sign-conversion -Wno-shorten-64-to-32 -Wno-shadow)
endif()
# TODO maybe clean up code and re-enable property
# set_property(TARGET ${LIBGENCMP_NAME} PROPERTY C_STANDARD 90)
# set_property(TARGET cmpClient         PROPERTY C_STANDARD 90)
# would have no effect:
# target_compile_features(${LIBGENCMP_NAME} PRIVATE c_std_90)
# target_compile_features(cmpClient         PRIVATE c_std_90)

add_library(${LIBGENCMP_NAME} SHARED
  "${PROJECT_SOURCE_DIR}/.github/workflows/build.yml"
  ${SRC_DIR}/genericCMPClient.c
)

if(NOT DEFINED GENCMP_NO_CLI)
add_executable(cmpClient
  ${SRC_DIR}/cmpClient.c
  ${SRC_DIR}/credential_loading.h
  ${SRC_DIR}/credential_loading.c
)

target_link_libraries(cmpClient
  ${LIBGENCMP_NAME}
  security-utilities::library
  $<$<BOOL:${USE_LIBCMP}>:cmp>
  # important: libcmp before libcrypto such that its contents are preferred
  OpenSSL::Crypto
  $<$<NOT:$<BOOL:${GENCMP_NO_TLS}>>:OpenSSL::SSL>
)
if(DEFINED ENV{SECUTILS_USE_UTA})
  target_link_libraries(cmpClient uta)
  target_link_directories(cmpClient PRIVATE "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}") # usually expands to /usr/local/lib
# set(CMAKE_INSTALL_RPATH "/usr/local/lib")
endif()
endif(NOT DEFINED GENCMP_NO_CLI)

target_link_libraries(${LIBGENCMP_NAME}
  $<$<NOT:$<BOOL:${GENCMP_NO_SECUTILS}>>:security-utilities::library>
  $<$<BOOL:${USE_LIBCMP}>:cmp>
  # important: libcmp before libcrypto such that its contents are preferred
  OpenSSL::Crypto
  $<$<NOT:$<BOOL:${GENCMP_NO_TLS}>>:OpenSSL::SSL>
)

set(INC_PUBLIC_HDRS
  ${INC_DIR}/genericCMPClient.h
  ${INC_DIR}/genericCMPClient_config.h
)
set_target_properties(${LIBGENCMP_NAME} PROPERTIES
  VERSION ${GENCMPCLIENT_VERSION} SOVERSION ${GENCMPCLIENT_VERSION_MAJOR}
  PUBLIC_HEADER "${INC_PUBLIC_HDRS}"
)

find_package(Git)
if(GIT_FOUND)
  # add --progress if the tool supports it
  execute_process(COMMAND ${CMAKE_COMMAND} -E env LC_ALL=C ${GIT_EXECUTABLE} --help submodule
    OUTPUT_VARIABLE _TMP_HELP
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  if("${_TMP_HELP}" MATCHES "--progress")
    set(GIT_PROGRESS "--progress") # gives lengthy output in CI runs
  endif()
  if("${_TMP_HELP}" MATCHES "--depth")
    set(GIT_DEPTH --depth 1) # used to speed up getting submodules
  endif()

  if(NOT DEFINED GENCMP_NO_SECUTILS)
    set(submodules libsecutils)
  endif()
  if(DEFINED USE_LIBCMP)
    set(submodules ${submodules} cmpossl)
  endif()

  add_custom_target(update
    COMMAND echo "updating repo and submodules"
    COMMAND git submodule update ${GIT_PROGRESS} ${submodules}
    COMMAND git fetch
    COMMAND git rebase
    )
else()
  MESSAGE(WARNING "Cannot find git, so cannot add 'update' targets for submodules")
endif()

if(NOT TARGET build)
  add_custom_target(build COMMAND make all)
endif()


# installation and uninstall

# default destination on Linux and macOS: "/usr/local"
#if(UNIX AND NOT APPLE)
#  set(CMAKE_INSTALL_PREFIX "/usr")
#else()
#  set(CMAKE_INSTALL_PREFIX "tmp")
#endif()
if(DEFINED ENV{ROOTFS})
  set(CMAKE_INSTALL_PREFIX $ENV{ROOTFS} CACHE PATH "comment" FORCE)
endif()
include(GNUInstallDirs) # CMAKE_INSTALL_PREFIX must be set before

install(FILES doc/Generic_CMP_client_API.pdf
  DESTINATION ${CMAKE_INSTALL_DOCDIR}-dev
  COMPONENT dev
  )

if(NOT DEFINED GENCMP_NO_CLI)
include(./Pod2Man)
POD2MAN("${CMAKE_CURRENT_SOURCE_DIR}/doc" cmpClient 1 "${CMAKE_INSTALL_MANDIR}" bin)
endif()

install(TARGETS ${LIBGENCMP_NAME}
  LIBRARY
    DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    COMPONENT lib
  PUBLIC_HEADER
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    COMPONENT dev
)

if(NOT DEFINED GENCMP_NO_CLI)
install(TARGETS cmpClient
  RUNTIME
  DESTINATION "${CMAKE_INSTALL_BINDIR}"
  COMPONENT bin
)
endif()

if(NOT TARGET uninstall)
  add_custom_target(uninstall
    COMMAND xargs -r -I% rm -vf \${DESTDIR}% <install_manifest.txt
    COMMAND rm -vfr "\${DESTDIR}${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}/{secutils,cmp}"
    COMMAND find . -path "./\${DESTDIR}${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR}" -empty | xargs -r rmdir
    COMMAND find . -path "./\${DESTDIR}${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}" -empty | xargs -r rmdir
    COMMAND rm -vfr "\${DESTDIR}${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/cmake/security-utilities" # seems not needed: ${PROJECT_NAME} cmpossl
    COMMAND find . -path "./\${DESTDIR}${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}/cmake" -empty | xargs -r rmdir
    COMMAND find . -path "./\${DESTDIR}${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}" -empty | xargs -r rmdir
    COMMAND rm -vfr "\${DESTDIR}${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_DOCDIR}-dev"
    COMMAND find . -path "./\${DESTDIR}${CMAKE_INSTALL_PREFIX}/share/man/man1" -empty | xargs -r rmdir
    COMMAND find . -path "./\${DESTDIR}${CMAKE_INSTALL_PREFIX}/share/man" -empty | xargs -r rmdir
    COMMAND find . -path "./\${DESTDIR}${CMAKE_INSTALL_PREFIX}/share/doc" -empty | xargs -r rmdir
    COMMAND find . -path "./\${DESTDIR}${CMAKE_INSTALL_PREFIX}/share" -empty | xargs -r rmdir
)
endif()


# cleaning

# https://stackoverflow.com/questions/9680420/looking-for-a-cmake-clean-command-to-clear-up-cmake-output/78133906#78133906

set_property(
  DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  APPEND
  PROPERTY ADDITIONAL_CLEAN_FILES
      # only works for predefined names as globbing would be done on cmake run
      ${CMAKE_CURRENT_BINARY_DIR}/cmpClient
      include/genericCMPClient_config.h
      compile_commands.json CMakeDoxyfile.in
      install_manifest.txt install_manifest_dev.txt install_manifest_lib.txt
      _CPack_Packages changelog.gz debian/.debhelper/
      )

# https://stackoverflow.com/a/78133906/2145180
if(NOT TARGET clean_all)
  add_custom_target(clean_all
    COMMAND ${CMAKE_BUILD_TOOL} clean
    COMMAND find . -name "*.o" -o -name "*.d" -o -regex "./libgencmp-.*" | xargs -r rm
# not needed and can go wrong for cmpossl:
#   COMMAND find . -path ./libsecutils/Makefile
#       | xargs -r -I% ${CMAKE_BUILD_TOOL} -C libsecutils clean
#   COMMAND find . -path     ./cmpossl/Makefile
#       | xargs -r -I% ${CMAKE_BUILD_TOOL} -C cmpossl     clean
    COMMAND find . -type d -name "build" | xargs -r rm -r
    # cowardly not doing rm -r ${CMAKE_BINARY_DIR}

    COMMAND rm CMakeCache.txt
    # after the following, cannot call this target again:
    COMMAND find . ( -name "*.cmake" -o -name Makefile )
#           -not -path ./libsecutils/* -not -path ./cmpossl/*
            -not -path ./libsecutils/src/libsecutils/security-utilities_libraryConfig.cmake
            -not -path ./libsecutils/src/util/security-utilities_icvutilConfig.cmake
            -not -path ./libsecutils/coverage/Makefile
            | xargs -r rm
    COMMAND find . -name CMakeFiles
#           -not -path ./libsecutils/* -not -path ./cmpossl/*
            | xargs -r rm -r
    COMMAND find . -type d -empty      | xargs -r rmdir
    COMMAND find . -type d -empty      | xargs -r rmdir
    COMMAND find . -type d -empty      | xargs -r rmdir
    COMMAND find . -type d -empty      | xargs -r rmdir
    COMMAND find . -type d -empty      | xargs -r rmdir
    COMMAND find . -type d -empty      | xargs -r rmdir
    VERBATIM
 )
 endif()

# generate Debian etc. packages using CPack, relying on installation defined above
if(NOT DEFINED CPACK_PACKAGE_NAME)

SET(CPACK_PACKAGE_NAME ${PROJECT_NAME})
SET(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/siemens/gencmpclient")
SET(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
SET(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.txt")
SET(CPACK_PACKAGE_VENDOR "Siemens")
set(CPACK_PACKAGE_CONTACT "David von Oheimb <David.von.Oheimb@siemens.com>")
set(CPACK_PACKAGE_VERSION       ${GENCMPCLIENT_VERSION})
set(CPACK_PACKAGE_VERSION_MAJOR ${GENCMPCLIENT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${GENCMPCLIENT_VERSION_MINOR})
set(CPACK_STRIP_FILES ON)

set(CPACK_COMPONENT_LIB_DESCRIPTION "generic CMP client library
Generic CMP client library with high-level API based on OpenSSL
With extended support for certficate status checking using CRLs and/or OCSP")
set(CPACK_COMPONENT_DEV_DESCRIPTION "libgencmp C headers and documentation
Development support for libgencmp and cmpclient")
set(CPACK_COMPONENT_BIN_DESCRIPTION "CMP client command-line interface
A CLI application for exploring the use of the generic CMP client library")

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
  set(CPACK_GENERATOR "DEB")
  set(EXT "deb")

  # see also https://gitlab.kitware.com/cmake/cmake/-/issues/24929 and
  # https://stackoverflow.com/questions/46490448/how-i-can-add-a-changelog-in-deb-with-cmake
  add_custom_command(
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/debian/changelog"
    COMMAND gzip -cn9 "${CMAKE_CURRENT_SOURCE_DIR}/debian/changelog"
    > "${CMAKE_CURRENT_BINARY_DIR}/changelog.gz"
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/changelog.gz"
  )
  if(NOT TARGET changelog)
    add_custom_target(changelog ALL DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/changelog.gz")
  endif()

  set(CPACK_DEB_COMPONENT_INSTALL ON)
  set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
  set(CPACK_DEBIAN_LIB_PACKAGE_NAME "${PROJECT_NAME}")
  if(NOT DEFINED GENCMP_NO_CLI)
    set(CPACK_DEBIAN_BIN_PACKAGE_NAME "cmpclient")
  endif()
  set(CPACK_DEBIAN_DEV_PACKAGE_ARCHITECTURE "all")
  set(CPACK_DEBIAN_LIB_PACKAGE_SECTION "libs")
  set(CPACK_DEBIAN_DEV_PACKAGE_SECTION "devel")
  set(CPACK_DEBIAN_BIN_PACKAGE_SECTION "utils")
  set(CPACK_DEBIAN_PACKAGE_GENERATE_SHLIBS ON)
  set(CPACK_DEBIAN_ENABLE_COMPONENT_DEPENDS ON)
  set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
  # set(CPACK_DEBIAN_PACKAGE_DEBUG ON)
  # see above assignments
  # to CPACK_DEBIAN_PACKAGE_SHLIBDEPS_PRIVATE_DIRS or CMAKE_INSTALL_RPATH

  if(FALSE) # for now, disable dependencies to libs of subprojectx because their .so files for some reason already get included in the package:
    if(NOT DEFINED GENCMP_NO_SECUTILS)
      if(DEFINED USE_LIBCMP)
        set(CPACK_DEBIAN_PACKAGE_DEPENDS
            "libcmp (>= ${CPACK_PACKAGE_VERSION}), libsecutils (>= ${CPACK_PACKAGE_VERSION})")
      else()
        set(CPACK_DEBIAN_PACKAGE_DEPENDS "libsecutils (>= ${CPACK_PACKAGE_VERSION})")
      endif()
    else()
      if(DEFINED USE_LIBCMP)
        set(CPACK_DEBIAN_PACKAGE_DEPENDS "libcmp (>= ${CPACK_PACKAGE_VERSION})")
      else()
        set(CPACK_DEBIAN_PACKAGE_DEPENDS "")
      endif()
    endif()
  endif(FALSE)

  set(CPACK_DEBIAN_DEV_PACKAGE_DEPENDS "libgencmp (>= ${CPACK_PACKAGE_VERSION})")
  set(CPACK_DEBIAN_DEV_PACKAGE_SUGGESTS "libcmp-dev (>= ${CPACK_PACKAGE_VERSION}), libsecutils-dev (>= ${CPACK_PACKAGE_VERSION}), libssl-dev")
  # see also https://gitlab.kitware.com/cmake/cmake/-/issues/21834
  # CPack Deb does not create postinst when installing to /usr/lib/x86_64-linux-gnu
  set(CPACK_DEBIAN_LIB_PACKAGE_CONTROL_EXTRA "${CMAKE_CURRENT_SOURCE_DIR}/debian/extra/triggers")
  set(CPACK_DEBIAN_LIB_PACKAGE_CONTROL_STRICT_PERMISSION TRUE)

else(Linux)
  #if(APPLE)
  #  set(CPACK_GENERATOR "Bundle")
  #  set(EXT "bundle")
  #  set(CPACK_BUNDLE_NAME "${CPACK_PACKAGE_NAME}")
  #else()
    set(CPACK_GENERATOR "ZIP")
    set(EXT "zip")
  #endif(APPLE)
endif(CMAKE_SYSTEM_NAME MATCHES "Linux")

set(CPACK_SOURCE_GENERATOR "TGZ")
# https://stackoverflow.com/questions/6712000/cmake-cpack-package-installation-path-nightmare
#set(CPACK_SET_DESTDIR TRUE) # prevents package creation error when using cpack
set(CPACK_VERBATIM_VARIABLES YES)
set(CPACK_SOURCE_IGNORE_FILES
  ${CPACK_IGNORE_FILES}
  ~$
  /\\.git/
  \\.git$
  \\.deb$
  \\.gz$
  \\.zip$
  \\.so
  \\.dylib$
  \\.diff$
  /attic/
  /tmp/
  /Makefile$
  CMakeFiles/
  _CPack_Packages/
  \\.cmake$
  /CMakeCache.txt$
  /compile_commands.json$
  /install_manifest.*\\.txt$
  /changelog\.gz$
  /debian/tmp/
  \\.substvars$
  \\.log$
  /debian/\\.debhelper/
  /debian/files$
  /debian/debhelper-build-stamp
  /debian/${PROJECT_NAME}/
  /debian/${PROJECT_NAME}-dev/
  /debian/cmpclient/
  cmpClient$
  \\.1$
  \\.1\.gz$
  \\.crl$
  \\.der$
  \\.jar$
  \\.dsc$
  \\.build$
  \\.buildinfo$
  \\.changes$
  libsecutils.*
  cmpossl.*/
  cmp-ra-component.*/
  LightweightCmpRa/
  SimpleLra/
  credentials
  Mock/
  Insta/
  Simple/
  )

include(CPack)

# see also https://gitlab.kitware.com/cmake/cmake/-/issues/21832
# CPack Deb lacks a way to configure copyright files by component
foreach(component IN LISTS CPACK_COMPONENTS_ALL)
  if(${component} STREQUAL "lib" OR ${component} STREQUAL "bin")
    set(suffix "")
  else()
    set(suffix "-${component}")
  endif()
  if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    install(FILES
      "${CMAKE_CURRENT_SOURCE_DIR}/debian/copyright"
      "${CMAKE_CURRENT_BINARY_DIR}/changelog.gz"
      DESTINATION "${CMAKE_INSTALL_DOCDIR}${suffix}"
      COMPONENT ${component}
      )
  endif()
endforeach()

if(NOT TARGET ${EXT})
  set (pack_full_name
    "${CMAKE_CURRENT_BINARY_DIR}/${CPACK_PACKAGE_NAME}-dev_${CPACK_PACKAGE_VERSION}_all.${EXT}")
  add_custom_command(
    OUTPUT "${pack_full_name}"
    DEPENDS build
    COMMENT "Building packages possibly including doxygen run"
    COMMAND cpack # --config CPackConfig.cmake
    COMMAND cpack --config CPackSourceConfig.cmake
    )
  add_custom_target(${EXT} DEPENDS ${pack_full_name})
endif()

endif(NOT DEFINED CPACK_PACKAGE_NAME)


# submodules

macro(add_clean_target dir)
  add_custom_target(clean-${dir} COMMAND ${CMAKE_MAKE_PROGRAM} clean WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/${dir})
endmacro(add_clean_target)

if(NOT YOCTO_BUILD)

  # find_package(secutils ${CPACK_PACKAGE_VERSION})
  if(NOT DEFINED GENCMP_NO_SECUTILS AND NOT secutils_FOUND)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/libsecutils/CMakeLists.txt")
      if(GIT_FOUND)
        message(STATUS "fetching git submodule libsecutils")
        execute_process(COMMAND
          git submodule update ${GIT_PROGRESS} --init ${GIT_DEPTH} libsecutils
          WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
          RESULT_VARIABLE GIT_SUBMODULE_RESULT
          )
        if(NOT GIT_SUBMODULE_RESULT EQUAL "0")
          message(FATAL_ERROR "git failed with exit code ${GIT_SUBMODULE_RESULT}")
        endif()
      else()
        message(FATAL_ERROR "Git not found; please install git.")
      endif()
    endif()
    add_subdirectory(libsecutils)
    add_clean_target(libsecutils)
  endif()

  # find_package(cmp ${CPACK_PACKAGE_VERSION})
  if(DEFINED USE_LIBCMP AND NOT libcmp_FOUND)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmpossl/CMakeLists.txt")
      if(GIT_FOUND)
        message(STATUS "fetching git submodule cmpossl, which is deprecated")
        execute_process(COMMAND
          git submodule update ${GIT_PROGRESS} --init ${GIT_DEPTH} cmpossl
          WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
          RESULT_VARIABLE GIT_SUBMODULE_RESULT
          )
        if(NOT GIT_SUBMODULE_RESULT EQUAL "0")
          message(FATAL_ERROR "git failed with exit code ${GIT_SUBMODULE_RESULT}")
        endif()
      else()
        message(FATAL_ERROR "Git not found; please install git.")
      endif()
    endif()
    add_subdirectory(cmpossl)
    add_clean_target(cmpossl)
  endif()

endif()
